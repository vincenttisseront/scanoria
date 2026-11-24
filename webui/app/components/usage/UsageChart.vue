<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Courbe simple d'une mesure dans le temps (F14), en SVG, sans bibliothèque :
une ligne, l'aire dessous, le minimum et le maximum de la période. Les trous
(mesure absente) coupent la ligne. Lisible au lecteur d'écran par son titre.
-->

<script setup lang="ts">
const props = defineProps<{
  points: { at: string, value: number | null }[]
  label: string
  format: (v: number | null) => string
}>()

const W = 300
const H = 64

const values = computed(() => props.points.map(p => p.value).filter((v): v is number => typeof v === 'number'))
const max = computed(() => (values.value.length ? Math.max(...values.value) : 0))
const min = computed(() => (values.value.length ? Math.min(...values.value) : 0))

/** Segments continus de la courbe, en coordonnées du cadre. */
const segments = computed(() => {
  const n = props.points.length
  const span = max.value - min.value || 1
  const out: string[][] = []
  let cur: string[] = []
  props.points.forEach((p, i) => {
    if (typeof p.value !== 'number') {
      if (cur.length) out.push(cur)
      cur = []
      return
    }
    const x = n > 1 ? (i / (n - 1)) * W : W / 2
    const y = H - 4 - ((p.value - min.value) / span) * (H - 8)
    cur.push(`${x.toFixed(1)},${y.toFixed(1)}`)
  })
  if (cur.length) out.push(cur)
  return out
})
const areas = computed(() => segments.value.filter(s => s.length > 1).map((s) => {
  const first = s[0]!.split(',')[0]
  const last = s[s.length - 1]!.split(',')[0]
  return `${first},${H} ${s.join(' ')} ${last},${H}`
}))
</script>

<template>
  <figure class="space-y-1">
    <figcaption class="flex items-baseline justify-between text-xs text-muted">
      <span class="font-medium text-default">{{ label }}</span>
      <span v-if="values.length">{{ format(min) }} – {{ format(max) }}</span>
    </figcaption>
    <svg
      :viewBox="`0 0 ${W} ${H}`"
      preserveAspectRatio="none"
      class="h-16 w-full text-primary"
      role="img"
      :aria-label="values.length ? `${label} : ${format(min)} – ${format(max)}` : label"
    >
      <line
        x1="0"
        :y1="H - 0.5"
        :x2="W"
        :y2="H - 0.5"
        class="stroke-current opacity-20"
        stroke-width="1"
      />
      <polygon
        v-for="(a, i) in areas"
        :key="`a${i}`"
        :points="a"
        class="fill-current opacity-10"
      />
      <polyline
        v-for="(s, i) in segments"
        :key="`l${i}`"
        :points="s.join(' ')"
        fill="none"
        class="stroke-current"
        stroke-width="1.5"
        vector-effect="non-scaling-stroke"
        stroke-linejoin="round"
      />
    </svg>
  </figure>
</template>
