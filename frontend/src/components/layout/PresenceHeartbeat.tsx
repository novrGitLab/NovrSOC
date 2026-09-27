'use client';

import { useEffect } from 'react';
import { apiUrl, apiFetch } from '@/lib/api';

// Sends a presence heartbeat (POST /api/auth/heartbeat) every 2 minutes while the admin app is
// open, and immediately when the tab is hidden or shown, so Settings → Team can show who is
// online, away (tab hidden) or offline. Renders nothing.

const INTERVAL_MS = 2 * 60_000;

function beat(visible: boolean, state?: 'offline') {
    return apiFetch(apiUrl('/api/auth/heartbeat'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ visible, ...(state ? { state } : {}) }),
        // keepalive lets the sign-out beat finish even as the page navigates away.
        keepalive: true,
    }).catch(() => {});
}

/** Tell the backend this user signed out, so they show offline straight away. */
export function announceSignOut() {
    void beat(false, 'offline');
}

export function PresenceHeartbeat() {
    useEffect(() => {
        const send = () => void beat(document.visibilityState === 'visible');
        send();
        const id = setInterval(send, INTERVAL_MS);
        document.addEventListener('visibilitychange', send);
        return () => {
            clearInterval(id);
            document.removeEventListener('visibilitychange', send);
        };
    }, []);
    return null;
}
