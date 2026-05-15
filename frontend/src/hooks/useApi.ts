import { useState, useEffect, useCallback, useRef } from 'react';

interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  // Returns the freshly-fetched payload so callers that need to wait
  // for the new data (e.g. HostDetail after Mark-as-Owned) can ``await
  // refetch()`` instead of relying on a delayed re-render. The promise
  // resolves to ``null`` when the request errors — the error is also
  // exposed via the ``error`` field on the next render.
  refetch: () => Promise<T | null>;
}

export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = []): UseApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const refetch = useCallback(async (): Promise<T | null> => {
    setLoading(true);
    setError(null);
    try {
      const payload = await fetcherRef.current();
      setData(payload);
      return payload;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  return { data, loading, error, refetch };
}
