'use client';

import { useState } from 'react';
import { Send, Mail } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

export function TeamCommunication() {
    const [message, setMessage] = useState('');
    const [sending, setSending] = useState(false);
    const [result, setResult] = useState<Record<string, string> | null>(null);

    const send = async () => {
        if (!message.trim()) return;
        setSending(true);
        setResult(null);
        try {
            const res = await apiFetch(apiUrl('/api/secops/broadcast'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: message.trim() }),
            });
            const data = await res.json();
            setResult(data.results ?? { error: data.error || 'Broadcast failed' });
            if (res.ok) setMessage('');
        } catch {
            setResult({ error: 'Could not reach the broadcast service' });
        } finally {
            setSending(false);
        }
    };

    return (
        <div className="space-y-4">
            <div className="bg-card border border-border rounded-xl p-5 space-y-4">
                <div>
                    <h3 className="text-sm font-bold text-foreground mb-1">Broadcast to Analysts</h3>
                    <p className="text-xs text-foreground-muted">Security advisory, shift instructions, urgent notice — emailed to every analyst on the team.</p>
                </div>

                <textarea
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    rows={4}
                    placeholder="Security advisory, shift instructions, urgent notice…"
                    className="w-full border border-border rounded-lg px-3 py-2.5 text-sm bg-card resize-none focus:outline-none focus:border-purple text-foreground"
                />

                <div className="flex items-center gap-2">
                    <span className="flex items-center gap-1.5 text-xs font-bold px-3 py-1.5 rounded-lg border bg-purple/10 border-purple text-purple">
                        <Mail size={13} /> Email
                    </span>

                    <button
                        onClick={send}
                        disabled={sending || !message.trim()}
                        className="ml-auto flex items-center gap-1.5 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2 rounded-lg disabled:opacity-50 transition-colors"
                    >
                        <Send size={13} /> {sending ? 'Sending…' : 'Send Broadcast'}
                    </button>
                </div>

                {result && (
                    <div className="bg-card-muted rounded-lg p-3 space-y-1">
                        {Object.entries(result).map(([channel, status]) => (
                            <div key={channel} className="flex items-center gap-2 text-xs">
                                <div className={`w-1.5 h-1.5 rounded-full ${status === 'sent' ? 'bg-green' : 'bg-red'}`} />
                                <span className="font-bold capitalize text-foreground">{channel}:</span>
                                <span className={status === 'sent' ? 'text-green' : 'text-red'}>{status}</span>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
