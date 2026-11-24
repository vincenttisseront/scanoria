# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
"""Ordonnancement des modules d'une tâche (0.6, V3 et V5).

Le worker range les modules de la tâche du plus long au plus court (durées
mesurées, F14) et déclare le graphe (modules[].after, V3 : Syft avant les
modules qui lisent son SBOM). Le runner :
  - respecte le graphe ; il y ajoute toujours la règle de la 0.5 (un module
    qui lit le SBOM de l'analyse attend ceux qui en produisent un), si bien
    qu'une tâche sans graphe (plan antérieur à la 0.6, rejeu G11) garde le
    même enchaînement ;
  - lance les modules prêts dans l'ordre de la tâche, et en parallèle tant
    que la mémoire et les processeurs de l'appliance le permettent (G17) :
    chaque conteneur réserve sa limite mémoire (--memory) et ses processeurs
    (--cpus). Les modules courts remplissent les creux laissés par les longs.
Garantie : une tâche a toujours au moins un module en cours, même au-delà du
budget, comme avant la 0.6 (une place du runner = une tâche) ; seuls les
modules supplémentaires dépendent de la place restante. Le délai d'une tâche
ne peut donc pas dépasser celui de l'enchaînement séquentiel.
"""

import threading

from . import common, modules, sbom, testbed


class Budget:
    """Mémoire (Mo) et processeurs réservés par les conteneurs en cours, toutes tâches confondues."""

    def __init__(self):
        self.cv = threading.Condition()
        self.mem_total, self.cpu_total = 0, 1
        self.mem_used, self.cpu_used = 0, 0
        self.per_job = {}

    def configure(self, mem_total, cpu_total):
        with self.cv:
            self.mem_total, self.cpu_total = max(0, int(mem_total)), max(1, int(cpu_total))
            self.cv.notify_all()

    def admit(self, job_id, mem, cpu):
        """À appeler sous self.cv : réserve si possible, retourne True."""
        first = self.per_job.get(job_id, 0) == 0
        if not first and (self.mem_used + mem > self.mem_total or self.cpu_used + cpu > self.cpu_total):
            return False
        self.mem_used += mem
        self.cpu_used += cpu
        self.per_job[job_id] = self.per_job.get(job_id, 0) + 1
        return True

    def release(self, job_id, mem, cpu):
        with self.cv:
            self.mem_used = max(0, self.mem_used - mem)
            self.cpu_used = max(0, self.cpu_used - cpu)
            n = self.per_job.get(job_id, 0) - 1
            if n > 0:
                self.per_job[job_id] = n
            else:
                self.per_job.pop(job_id, None)
            self.cv.notify_all()

    def hold(self, job_id, mem, cpu):
        """Réservation pour la durée d'un bloc (récupération de la source)."""
        budget = self

        class _Hold:
            def __enter__(self):
                with budget.cv:
                    while not budget.admit(job_id, mem, cpu):
                        budget.cv.wait(1.0)

            def __exit__(self, *exc):
                budget.release(job_id, mem, cpu)
                return False
        return _Hold()


BUDGET = Budget()


def configure_from(reg):
    """Budget de l'appliance : mémoire hors réserve système et modules permanents, processeurs."""
    try:
        total = modules._meminfo_mb()
    except common.Fail:
        total = 0
    perm = sum(modules._res(e.get("manifest") or {}, "min_ram_mb") for e in reg["modules"].values()
               if e.get("enabled") and (e.get("manifest") or {}).get("type") in ("service", "runner"))
    BUDGET.configure(total - modules.RESERVED_RAM_MB - perm, modules._cpus())


def need(m):
    """(Mo, processeurs) réservés par le conteneur du module (mêmes valeurs que testbed.confined_args)."""
    res = m.get("resources") or {}
    cpu = res.get("min_cpu") if isinstance(res.get("min_cpu"), (int, float)) else 1
    return testbed.memory_mb(m), max(1, min(int(cpu), 64))


def produces_sbom(m):
    decl = m.get("outputs")
    return isinstance(decl, dict) and "cyclonedx" in decl and not sbom.consumes(m)


def dependencies(job, runnable):
    """{id: {ids}} : graphe de la tâche (after) plus la règle SBOM, limité aux modules lancés."""
    ids = {e["id"] for e, _ in runnable}
    declared = {item["id"]: set(item.get("after") or []) for item in job.get("modules") or []}
    producers = {e["id"] for e, s in runnable if produces_sbom(s["manifest"])}
    deps = {}
    for e, s in runnable:
        d = set(declared.get(e["id"], set()))
        if sbom.consumes(s["manifest"]):
            d |= producers
        d.discard(e["id"])
        deps[e["id"]] = d & ids
    return deps


def run_all(job_id, runnable, deps, run_one, budget=None, max_parallel=None, on_start_error=None):
    """Lance run_one(entry, spec) pour chaque module, graphe et budget respectés ; attend la fin.

    run_one ne doit pas lever (le runner attrape déjà les erreurs d'un module)."""
    budget = budget or BUDGET
    remaining = list(runnable)
    done, running, threads = set(), set(), []

    def worker(entry, spec, mem, cpu):
        try:
            run_one(entry, spec)
        finally:
            budget.release(job_id, mem, cpu)
            with budget.cv:
                running.discard(entry["id"])
                done.add(entry["id"])
                budget.cv.notify_all()

    with budget.cv:
        while remaining or running:
            started = False
            ready = [it for it in remaining if not (deps.get(it[0]["id"], set()) - done)]
            if not ready and not running and remaining:
                ready = remaining[:1]      # graphe impossible (cycle) : on avance quand même, dans l'ordre
            for it in ready:
                if max_parallel is not None and len(running) >= max_parallel:
                    break
                mem, cpu = need(it[1]["manifest"])
                if not budget.admit(job_id, mem, cpu):
                    continue
                remaining.remove(it)
                running.add(it[0]["id"])
                th = threading.Thread(target=worker, args=(it[0], it[1], mem, cpu),
                                      name="mod-%s" % it[0]["id"], daemon=True)
                try:
                    th.start()
                except RuntimeError as e:
                    # Plus de thread disponible : réservation rendue, module en erreur d'infrastructure (G12).
                    budget.release(job_id, mem, cpu)
                    running.discard(it[0]["id"])
                    done.add(it[0]["id"])
                    if on_start_error is not None:
                        on_start_error(it[0], e)
                    started = True
                    continue
                threads.append(th)
                started = True
            if not started:
                budget.cv.wait(1.0)
    for th in threads:
        th.join()
