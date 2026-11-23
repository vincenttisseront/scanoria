// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Appels à l'API : en-tête CSRF, redirection vers la connexion sur 401,
// messages d'erreur traduits à partir du code renvoyé par le serveur.

interface FetchLikeError {
  statusCode?: number
  status?: number
  data?: { data?: { code?: string }, code?: string }
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export interface ApiOptions {
  method?: Method
  body?: BodyInit | Record<string, unknown> | null
  query?: Record<string, unknown>
  headers?: Record<string, string>
}

export function errorCode(err: unknown): string | undefined {
  const e = err as FetchLikeError
  return e?.data?.data?.code ?? e?.data?.code
}

export function errorStatus(err: unknown): number | undefined {
  const e = err as FetchLikeError
  return e?.statusCode ?? e?.status
}

export function useApi() {
  const session = useSession()
  const { t, te } = useI18n()

  async function api<T>(url: string, opts: ApiOptions = {}): Promise<T> {
    const method = opts.method ?? 'GET'
    const headers: Record<string, string> = { ...opts.headers }
    if (method !== 'GET' && session.state.value.csrf) headers['x-csrf-token'] = session.state.value.csrf
    try {
      const res: unknown = await $fetch(url, { method, body: opts.body ?? undefined, query: opts.query, headers })
      return res as T
    }
    catch (err) {
      if (errorStatus(err) === 401 && url !== '/api/auth/login') {
        session.clear()
        await navigateTo('/login')
      }
      else if (errorCode(err) === 'E_PASSWORD_CHANGE_REQUIRED') {
        await navigateTo('/account')
      }
      throw err
    }
  }

  function errorMessage(err: unknown): string {
    const code = errorCode(err)
    if (code && te(`errors.${code}`)) return t(`errors.${code}`)
    if (errorStatus(err) === undefined) return t('errors.network')
    return t('errors.generic')
  }

  return { api, errorMessage }
}
