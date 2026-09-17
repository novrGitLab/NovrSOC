'use client';

import { useEffect, useState } from 'react';
import { Mail, Plus, X } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Email Monitoring — every message that passed through the NovrSOC MX proxy, with its verdict.
//
// Nothing here is simulated. Until a client repoints their MX and the mail host starts reporting
// verdicts, the page shows setup instructions and an empty log, because an email security page
// showing sample messages is indistinguishable from one showing real mail.

interface EmailLog {
    id?: string;
    message_id: string;
    from_address: string;
    to_address: string;
    subject?: string | null;
    verdict: string;
    score?: number;
    received_at: string;
    has_attachment?: boolean;
}

interface Stats {
    total: number; clean: number; spam: number; phishing: number;
    malware: number; suspicious: number; period: string; error?: string;
}

interface ProxyDomain {
    domain: string; real_mx: string; forward_to: string; active: boolean;
}

const MAIL_HOST = 'mail.cybernovr.com';

const VERDICT_DOT: Record<string, string> = {
    clean: 'bg-green', phishing: 'bg-red-500', malware: 'bg-red-700',
    spam: 'bg-amber-500', suspicious: 'bg-orange',
};
const VERDICT_BADGE: Record<string, string> = {
    clean: 'bg-green/10 text-green', phishing: 'bg-red-500/10 text-red-500',
    malware: 'bg-red-500/20 text-red-500', spam: 'bg-amber-500/10 text-amber-500',
    suspicious: 'bg-orange/10 text-orange',
};

const SETUP_STEPS = [
    { step: '01', text: 'Add your domain below, with its current MX host and the address clean mail should reach.' },
    { step: '02', text: `Change your MX record to ${MAIL_HOST} at priority 10.` },
    { step: '03', text: 'Keep your existing MX as a lower-priority backup (priority 20) so mail still flows if the proxy is unreachable.' },
    { step: '04', text: 'Mail then routes through NovrSOC, is scanned, and is forwarded to your mailbox. Verdicts appear below.' },
];

const TABLE_SQL = `CREATE TABLE IF NOT EXISTS public.email_logs (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id       TEXT UNIQUE NOT NULL,
  org_id           TEXT NOT NULL,
  from_address     TEXT NOT NULL,
  to_address       TEXT NOT NULL,
  subject          TEXT,
  verdict          TEXT DEFAULT 'clean',
  score            INTEGER DEFAULT 0,
  reasons          TEXT[] DEFAULT '{}',
  received_at      TIMESTAMPTZ DEFAULT NOW(),
  size_bytes       INTEGER DEFAULT 0,
  has_attachment   BOOLEAN DEFAULT false,
  attachment_names TEXT[] DEFAULT '{}',
  source_ip        TEXT,
  source_country   TEXT,
  dmarc_result     TEXT,
  spf_result       TEXT,
  dkim_result      TEXT
);
ALTER TABLE public.email_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "email_logs_service" ON public.email_logs
  FOR ALL USING (auth.role() = 'service_role');

CREATE TABLE IF NOT EXISTS public.email_proxy_domains (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain     TEXT UNIQUE NOT NULL,
  org_id     TEXT NOT NULL,
  real_mx    TEXT NOT NULL,
  forward_to TEXT NOT NULL,
  active     BOOLEAN DEFAULT true,
  added_at   TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.email_proxy_domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY "email_proxy_domains_service" ON public.email_proxy_domains
  FOR ALL USING (auth.role() = 'service_role');`;

export function EmailMonitoring() {
    const [stats, setStats] = useState<Stats | null>(null);
    const [logs, setLogs] = useState<EmailLog[]>([]);
    const [domains, setDomains] = useState<ProxyDomain[]>([]);
    const [loading, setLoading] = useState(true);
    const [setupError, setSetupError] = useState<string | null>(null);

    const [showAdd, setShowAdd] = useState(false);
    const [form, setForm] = useState({ domain: '', real_mx: '', forward_to: '' });
    const [saving, setSaving] = useState(false);
    const [saveError, setSaveError] = useState<string | null>(null);

    const load = () => {
        const get = (path: string) => apiFetch(apiUrl(path), { cache: 'no-store' }).then((r) => r.json());
        Promise.allSettled([
            get('/api/email-proxy/stats'),
            get('/api/email-proxy/logs?limit=50'),
            get('/api/email-proxy/domains'),
        ]).then(([s, l, d]) => {
            if (s.status === 'fulfilled') setStats(s.value as Stats);
            if (l.status === 'fulfilled') setLogs(Array.isArray(l.value?.logs) ? l.value.logs : []);
            if (d.status === 'fulfilled') setDomains(Array.isArray(d.value?.domains) ? d.value.domains : []);

            // The backend answers 200 with an explicit `error` when the tables don't exist yet,
            // so the page can show the setup step rather than rendering a silent empty list.
            const err = (s.status === 'fulfilled' && s.value?.error)
                || (d.status === 'fulfilled' && d.value?.error)
                || (l.status === 'fulfilled' && l.value?.error);
            setSetupError(typeof err === 'string' ? err : null);
            setLoading(false);
        });
    };

    useEffect(load, []);

    const addDomain = async () => {
        setSaving(true);
        setSaveError(null);
        try {
            const res = await apiFetch(apiUrl('/api/email-proxy/domains'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            });
            const data = await res.json();
            if (!res.ok) { setSaveError(data?.error ?? `HTTP ${res.status}`); return; }
            setShowAdd(false);
            setForm({ domain: '', real_mx: '', forward_to: '' });
            load();
        } catch {
            setSaveError('Could not reach the backend.');
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="space-y-5">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-start gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-purple/10 flex items-center justify-center shrink-0">
                        <Mail className="w-4 h-4 text-purple" />
                    </div>
                    <div>
                        <h1 className="text-lg font-black text-foreground">Email Monitoring</h1>
                        <p className="text-xs text-foreground-muted">Email Security · Inbound mail scanned by the NovrSOC MX proxy</p>
                    </div>
                </div>
                <button onClick={() => setShowAdd(true)}
                    className="flex items-center gap-1.5 bg-purple text-white text-xs font-bold px-4 py-2.5 rounded-xl hover:opacity-90 transition-opacity">
                    <Plus size={14} /> Add Domain
                </button>
            </div>

            {setupError && (
                <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl p-4">
                    <p className="text-sm font-bold text-amber-500">Database tables not set up</p>
                    <p className="text-xs text-foreground-muted mt-1 leading-relaxed">{setupError}</p>
                    <details className="mt-3">
                        <summary className="cursor-pointer text-[11px] font-bold text-purple">Show SQL</summary>
                        <pre className="bg-card-muted/60 border border-border rounded-xl p-3 text-[10px] text-foreground overflow-x-auto scrollbar-thin mt-2"><code>{TABLE_SQL}</code></pre>
                    </details>
                </div>
            )}

            {/* Setup guidance while no domain is proxied. */}
            {!loading && domains.length === 0 && (
                <div className="bg-card border border-border rounded-xl p-5">
                    <h3 className="text-sm font-black text-foreground mb-1">Email proxy not configured</h3>
                    <p className="text-xs text-foreground-muted mb-4 leading-relaxed max-w-2xl">
                        Mail is only scanned once a domain&apos;s MX record points at NovrSOC. Nothing is
                        monitored until then — this page will stay empty rather than showing example traffic.
                    </p>
                    <div className="space-y-2 mb-4">
                        {SETUP_STEPS.map((s) => (
                            <div key={s.step} className="flex items-start gap-3">
                                <div className="w-6 h-6 rounded-full bg-purple/10 flex items-center justify-center shrink-0 mt-0.5">
                                    <span className="text-[9px] font-black text-purple">{s.step}</span>
                                </div>
                                <span className="text-xs text-foreground-muted leading-relaxed">{s.text}</span>
                            </div>
                        ))}
                    </div>
                    <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl p-3">
                        <p className="text-[11px] text-amber-500 font-bold mb-1">Before mail can be reported</p>
                        <p className="text-[10px] text-foreground-muted leading-relaxed">
                            The mail host must send <code className="font-mono">EMAIL_PROXY_TOKEN</code> as an{' '}
                            <code className="font-mono">X-NovrSOC-Proxy-Token</code> header on every verdict it posts.
                            Verdict reporting is refused until that token is set on the backend — an
                            unauthenticated endpoint here would let anyone write into your mail log.
                        </p>
                    </div>
                </div>
            )}

            {/* Stats — rendered once mail has actually been scanned. */}
            {stats && stats.total > 0 && (
                <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
                    {[
                        { label: `Total (${stats.period})`, value: stats.total, tone: 'text-foreground' },
                        { label: 'Clean', value: stats.clean, tone: 'text-green' },
                        { label: 'Spam', value: stats.spam, tone: 'text-amber-500' },
                        { label: 'Phishing', value: stats.phishing, tone: 'text-red-500' },
                        { label: 'Malware', value: stats.malware, tone: 'text-red-500' },
                        { label: 'Suspicious', value: stats.suspicious, tone: 'text-orange' },
                    ].map((s) => (
                        <div key={s.label} className="bg-card border border-border rounded-xl p-4 text-center">
                            <div className={`text-2xl font-black ${s.tone}`}>{s.value}</div>
                            <div className="text-[10px] text-foreground-muted mt-0.5">{s.label}</div>
                        </div>
                    ))}
                </div>
            )}

            {domains.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-5">
                    <h3 className="text-sm font-black text-foreground mb-3">Monitored Domains</h3>
                    <div className="space-y-2">
                        {domains.map((d) => (
                            <div key={d.domain} className="flex items-center gap-3 p-3 bg-card-muted/50 rounded-xl flex-wrap">
                                <div className={`w-2 h-2 rounded-full shrink-0 ${d.active ? 'bg-green' : 'bg-card-muted'}`} />
                                <span className="text-sm font-bold text-foreground flex-1 min-w-0">{d.domain}</span>
                                <span className="text-[11px] text-foreground-muted">MX {d.real_mx} → {d.forward_to}</span>
                                <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase ${d.active ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'}`}>
                                    {d.active ? 'Active' : 'Paused'}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Log */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-3 flex-wrap">
                    <h3 className="text-sm font-black text-foreground">Email Log</h3>
                    <span className="text-[10px] text-foreground-muted">{logs.length} messages</span>
                </div>

                {loading ? (
                    <div className="p-5 space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-10 bg-card-muted rounded animate-pulse" />)}</div>
                ) : logs.length === 0 ? (
                    <div className="text-center py-14 px-6">
                        <p className="text-sm font-bold text-foreground mb-1">No messages scanned yet</p>
                        <p className="text-xs text-foreground-muted max-w-md mx-auto">
                            {domains.length === 0
                                ? 'Add a domain and repoint its MX record to begin scanning.'
                                : 'The domain is configured but no mail has been reported yet. Confirm the MX change has propagated and that the mail host is posting verdicts.'}
                        </p>
                    </div>
                ) : (
                    <div className="divide-y divide-border">
                        {logs.map((log) => (
                            <div key={log.message_id} className="flex items-center gap-3 px-5 py-3 hover:bg-card-muted/40">
                                <div className={`w-2 h-2 rounded-full shrink-0 ${VERDICT_DOT[log.verdict] ?? 'bg-card-muted'}`} />
                                <div className="flex-1 min-w-0">
                                    <div className="text-xs font-bold text-foreground truncate">{log.subject || '(no subject)'}</div>
                                    <div className="text-[10px] text-foreground-muted truncate">
                                        {log.from_address} → {log.to_address}
                                    </div>
                                </div>
                                {log.has_attachment && <span className="text-[10px] text-foreground-muted shrink-0" title="Has attachment">📎</span>}
                                <div className="text-right shrink-0">
                                    <div className={`text-[9px] font-black px-2 py-0.5 rounded-full uppercase ${VERDICT_BADGE[log.verdict] ?? 'bg-card-muted text-foreground-muted'}`}>
                                        {log.verdict}
                                    </div>
                                    <div className="text-[10px] text-foreground-muted mt-0.5">
                                        {new Date(log.received_at).toLocaleTimeString('en-GB', { timeZone: 'Africa/Lagos' })} WAT
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Add domain */}
            {showAdd && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setShowAdd(false)}>
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-md" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-black text-foreground">Add Domain to Monitor</h3>
                            <button onClick={() => setShowAdd(false)} className="text-foreground-muted hover:text-foreground" aria-label="Close"><X size={18} /></button>
                        </div>
                        <div className="space-y-3">
                            {([
                                ['domain', 'Domain', 'cybernovr.com'],
                                ['real_mx', 'Current MX (your real mail server)', 'mx.zoho.com'],
                                ['forward_to', 'Forward clean mail to', 'rayne@cybernovr.com'],
                            ] as const).map(([key, label, placeholder]) => (
                                <div key={key}>
                                    <label htmlFor={`ep-${key}`} className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1 block">{label}</label>
                                    <input
                                        id={`ep-${key}`}
                                        value={form[key]}
                                        onChange={(e) => setForm((p) => ({ ...p, [key]: e.target.value }))}
                                        placeholder={placeholder}
                                        className="w-full bg-card border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-purple"
                                    />
                                </div>
                            ))}
                            <div className="bg-purple/5 border border-purple/20 rounded-xl p-3">
                                <p className="text-[10px] font-bold text-purple mb-1">After adding, change your MX record to:</p>
                                <code className="text-[10px] text-purple font-mono">Priority 10 · {MAIL_HOST}</code>
                            </div>
                            {saveError && <p className="text-[11px] text-red-500">{saveError}</p>}
                        </div>
                        <div className="flex gap-3 mt-4">
                            <button onClick={() => setShowAdd(false)} className="flex-1 py-2.5 text-sm font-bold text-foreground-muted bg-card-muted rounded-xl hover:text-foreground transition-colors">
                                Cancel
                            </button>
                            <button onClick={() => void addDomain()} disabled={saving || !form.domain.trim()}
                                className="flex-1 py-2.5 text-sm font-bold text-white bg-purple rounded-xl hover:opacity-90 disabled:opacity-50 transition-opacity">
                                {saving ? 'Adding…' : 'Add Domain'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
