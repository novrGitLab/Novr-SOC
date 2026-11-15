'use client';

import { useCallback, useEffect, useState } from 'react';

type Loaded<T> = { loader: unknown; tick: number; data: T | undefined; error: unknown };

/** Loads one API resource. `data` is undefined while loading; `error` holds the failure (shown with
 *  ApiErrorState). Re-runs when `loader` changes (memoise it with useCallback on its inputs) and on
 *  `reload()`. A result belongs to the loader and reload that produced it, so after an organization switch
 *  the previous organization's data is never shown, and a superseded request is discarded. */
export function useResource<T>(loader: () => Promise<T>) {
    const [tick, setTick] = useState(0);
    const [state, setState] = useState<Loaded<T>>({ loader: null, tick: -1, data: undefined, error: null });

    useEffect(() => {
        let live = true;
        loader().then(
            (data) => { if (live) setState({ loader, tick, data, error: null }); },
            (error: unknown) => { if (live) setState({ loader, tick, data: undefined, error }); },
        );
        return () => { live = false; };
    }, [loader, tick]);

    const current = state.loader === loader && state.tick === tick;
    const reload = useCallback(() => setTick((t) => t + 1), []);
    /** Replace the data with a mutation's result (the API returns the updated record). */
    const setData = useCallback((data: T) => setState({ loader, tick, data, error: null }), [loader, tick]);

    return { data: current ? state.data : undefined, error: current ? state.error : null, reload, setData };
}
