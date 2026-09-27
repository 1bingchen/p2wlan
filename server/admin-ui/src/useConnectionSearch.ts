import { useCallback } from 'react'
import { useLocation, useSearchParams, type SetURLSearchParams } from 'react-router-dom'

/** Keep the explicit resource return context while editing workspace URL state. */
export function useConnectionSearchParams() {
  const [params, setParams] = useSearchParams()
  const { state } = useLocation()
  const update = useCallback<SetURLSearchParams>((next, options) => {
    setParams(next, { state, ...options })
  }, [setParams, state])
  return [params, update] as const
}
