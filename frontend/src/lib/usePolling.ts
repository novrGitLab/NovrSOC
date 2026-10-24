'use client';

// Re-run `load` every `intervalMs` while the tab is visible (P24). A hidden tab is not polled;
// when it becomes visible again and the last run is older than the interval, `load` runs at once,
// so a page left in the background is current as soon as someone looks at it. The first load is
// the component's own (on mount); this only keeps it fresh. `enabled: false` pauses it.

import { useEffect, useRef } from 'react';

export function usePolling(load: () => unknown, intervalMs: number, enabled = true): void {
    const loadRef = useRef(load);
    useEffect(() => { loadRef.current = load; }, [load]);

    useEffect(() => {
        if (!enabled || typeof document === 'undefined') return;
        let last = Date.now();
        const run = () => { last = Date.now(); void loadRef.current(); };
        const id = setInterval(() => { if (document.visibilityState === 'visible') run(); }, intervalMs);
        const onVisible = () => { if (document.visibilityState === 'visible' && Date.now() - last >= intervalMs) run(); };
        document.addEventListener('visibilitychange', onVisible);
        return () => { clearInterval(id); document.removeEventListener('visibilitychange', onVisible); };
    }, [intervalMs, enabled]);
}
