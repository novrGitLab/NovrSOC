'use client';

import { useEffect, useState } from 'react';
import { AlertTriangle, ExternalLink } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Billing & platform analytics.
//
// This page used to run entirely on a hardcoded MOCK_BILLING_ORGS list — two invented
// organisations ("Dangote Group", Professional plan, $799/mo, trial expiring) driving an
// invented MRR, plan distribution, per-client payment status and renewal schedule. There is no
// billing table anywhere in this stack, so every one of those figures was fiction.
//
// What's here now: real counts from real endpoints (organisations, platform users, TheHive
// incidents, Wazuh alerts, SLA credits), plus an explicit revenue *projection* the operator
// drives by entering a price per client. The projection is labelled as one and the input is
// remembered per browser — it isn't billing data, and nothing here should be read as invoiced.
//
// Per-client payment status, plan distribution and renewals are gone rather than reconstructed:
// they need an actual billing table with invoices and payment state, not a guess keyed off the
// org list.

interface Org { id: string; name: string; slug: string }
interface SLASummary { total_endpoints: number; breached: number; total_credits_usd: number }
interface IncidentSummary { total: number; critical: number; resolvedToday: number }

const PRICE_KEY = 'novrsoc.billing.price-per-client';

export default function BillingPage() {
    const [orgs, setOrgs] = useState<Org[] | null>(null);
    const [orgsError, setOrgsError] = useState<string | null>(null);
    const [userCount, setUserCount] = useState<number | null>(null);
    const [incidents, setIncidents] = useState<IncidentSummary | null>(null);
    const [alertCount, setAlertCount] = useState<number | null>(null);
    const [slaSummary, setSlaSummary] = useState<SLASummary | null>(null);
    const [slaError, setSlaError] = useState(false);

    const [pricePerClient, setPricePerClient] = useState('');
    const [hydrated, setHydrated] = useState(false);

    // localStorage only after mount — it doesn't exist during prerender, and seeding state from
    // it in the initial render would desync server and client markup.
    //
    // react-hooks/set-state-in-effect is disabled here deliberately: this effect subscribes to
    // an external store at mount rather than deriving state React already holds, which is the
    // case that rule carves out. useSyncExternalStore would satisfy it but is heavy machinery
    // for reading one string once.
    useEffect(() => {
        try {
            const saved = localStorage.getItem(PRICE_KEY);
            // eslint-disable-next-line react-hooks/set-state-in-effect -- one-shot hydrate from localStorage; see above
            if (saved) setPricePerClient(saved);
        } catch {
            // Blocked site data — the input just starts empty.
        }
        setHydrated(true);
    }, []);

    useEffect(() => {
        if (!hydrated) return;
        try { localStorage.setItem(PRICE_KEY, pricePerClient); } catch { /* best effort */ }
    }, [pricePerClient, hydrated]);

    useEffect(() => {
        apiFetch(apiUrl('/api/organisations'), { cache: 'no-store' })
            .then(async (r) => {
                const data = await r.json();
                if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`);
                return data;
            })
            .then(async (data) => {
                const list: Org[] = Array.isArray(data?.organisations) ? data.organisations : [];
                setOrgs(list);

                // No "all platform users" endpoint exists — users are only listed per org, so
                // the total is summed across orgs. Failures per org are ignored rather than
                // zeroing the whole count.
                const counts = await Promise.allSettled(
                    list.map((o) => apiFetch(apiUrl(`/api/organisations/${o.id}/users`), { cache: 'no-store' }).then((r) => r.json()))
                );
                const total = counts.reduce((sum, c) => {
                    if (c.status !== 'fulfilled') return sum;
                    const users = Array.isArray(c.value?.users) ? c.value.users : Array.isArray(c.value) ? c.value : [];
                    return sum + users.length;
                }, 0);
                setUserCount(total);
            })
            .catch((err) => setOrgsError(err instanceof Error ? err.message : 'Failed to load organisations'));

        apiFetch(apiUrl('/api/incidents'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => { if (d?.summary) setIncidents(d.summary as IncidentSummary); })
            .catch(() => {});

        apiFetch(apiUrl('/api/wazuh/trend?range=30d'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => {
                if (Array.isArray(d)) setAlertCount(d.reduce((s: number, p: { alerts?: number }) => s + (p.alerts ?? 0), 0));
            })
            .catch(() => {});

        apiFetch(apiUrl('/api/sla/overview'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setSlaSummary(d?.summary ?? null))
            .catch(() => setSlaError(true));
    }, []);

    const clientCount = orgs?.length ?? null;
    const price = Number(pricePerClient);
    const validPrice = pricePerClient.trim() !== '' && Number.isFinite(price) && price >= 0;
    const mrr = validPrice && clientCount !== null ? price * clientCount : null;

    return (
        <div className="space-y-5">
            <div>
                <h1 className="text-lg font-black text-foreground">Billing & Platform Analytics</h1>
                <p className="text-xs text-foreground-muted">Administration · Live client, user and workload counts, plus SLA credit liability</p>
            </div>

            {/* Real counts */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                    { label: 'Total Clients', value: clientCount, sub: 'organisations table', tone: 'text-purple' },
                    { label: 'Platform Users', value: userCount, sub: 'across all organisations', tone: 'text-foreground' },
                    { label: 'Open Incidents', value: incidents?.total ?? null, sub: 'TheHive, severity high+', tone: 'text-amber' },
                    { label: 'Alerts (30d)', value: alertCount, sub: 'Wazuh indexer', tone: 'text-blue' },
                ].map((s) => (
                    <div key={s.label} className="bg-card border border-border rounded-xl p-4">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{s.label}</p>
                        <p className={`text-2xl font-black mt-1 ${s.tone}`}>{s.value === null ? '—' : s.value.toLocaleString()}</p>
                        <p className="text-[10px] text-foreground-muted mt-0.5">{s.sub}</p>
                    </div>
                ))}
            </div>

            {orgsError && (
                <p className="text-[11px] text-amber">Organisations unavailable: {orgsError}</p>
            )}

            {/* Revenue projection */}
            <div className="bg-card border border-border rounded-xl p-5">
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1">Revenue Projection</p>
                <p className="text-[11px] text-foreground-muted mb-4">
                    A projection, not billing data — no invoices or payment status are tracked in this platform yet.
                </p>
                <div className="flex flex-wrap items-end gap-5">
                    <div>
                        <label htmlFor="price-per-client" className="block text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1.5">
                            Price per client / month (₦)
                        </label>
                        <input
                            id="price-per-client"
                            type="number"
                            min="0"
                            inputMode="numeric"
                            value={pricePerClient}
                            onChange={(e) => setPricePerClient(e.target.value)}
                            placeholder="450000"
                            className="bg-card border border-border rounded-lg px-3 py-2 text-sm text-foreground w-44 focus:outline-none focus:border-purple"
                        />
                    </div>
                    <div>
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1.5">Projected MRR</p>
                        <p className="text-2xl font-black text-purple">
                            {mrr === null ? '—' : `₦${mrr.toLocaleString()}`}
                        </p>
                        <p className="text-[10px] text-foreground-muted mt-0.5">
                            {clientCount === null
                                ? 'Client count unavailable'
                                : validPrice
                                    ? `${clientCount} client${clientCount === 1 ? '' : 's'} × ₦${price.toLocaleString()}`
                                    : 'Enter a price to project'}
                        </p>
                    </div>
                </div>
                <p className="text-[10px] text-foreground-muted mt-4">
                    The price you enter is remembered in this browser only.
                </p>
            </div>

            {/* SLA credit liability — live from the Recovery Credit feature's real endpoint */}
            <div className="bg-card border border-border rounded-xl p-4">
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-3">SLA Credit Liability</p>
                {slaError ? (
                    <p className="text-xs text-foreground-muted">Could not reach the SLA service.</p>
                ) : !slaSummary ? (
                    <div className="h-16 bg-card-muted rounded-lg animate-pulse" />
                ) : (
                    <div className="flex items-center justify-between gap-4 flex-wrap">
                        <div className="flex items-center gap-3">
                            {slaSummary.total_credits_usd > 0 && <AlertTriangle className="w-5 h-5 text-amber shrink-0" />}
                            <div>
                                <p className={`text-2xl font-black ${slaSummary.total_credits_usd > 0 ? 'text-amber' : 'text-green'}`}>
                                    ${slaSummary.total_credits_usd.toLocaleString()}
                                </p>
                                <p className="text-[10px] text-foreground-muted">
                                    {slaSummary.breached} of {slaSummary.total_endpoints} monitored endpoint{slaSummary.total_endpoints === 1 ? '' : 's'} in breach this month
                                </p>
                            </div>
                        </div>
                        <a href="/admin/data/sla" className="flex items-center gap-1 text-[11px] font-bold text-purple hover:underline">
                            View Recovery Credit <ExternalLink size={12} />
                        </a>
                    </div>
                )}
            </div>

            {/* Client roster — real orgs, no invented payment state */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="p-4 border-b border-border">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Clients</p>
                </div>
                {orgs === null ? (
                    <div className="p-4 space-y-2">
                        {Array.from({ length: 2 }).map((_, i) => <div key={i} className="h-10 bg-card-muted rounded animate-pulse" />)}
                    </div>
                ) : orgs.length === 0 ? (
                    <p className="text-xs text-foreground-muted text-center py-8">No organisations yet.</p>
                ) : (
                    <div className="divide-y divide-border">
                        {orgs.map((o) => (
                            <div key={o.id} className="p-3 flex items-center justify-between gap-3">
                                <div className="min-w-0">
                                    <p className="text-sm font-semibold text-foreground truncate">{o.name}</p>
                                    <p className="text-[10px] text-foreground-muted font-mono">{o.slug}</p>
                                </div>
                                <a href={`/admin/customers/${o.id}`} className="text-[11px] font-bold text-purple hover:underline shrink-0">
                                    View →
                                </a>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <p className="text-[10px] text-foreground-muted">
                Per-client payment status, plan distribution and renewal dates are not shown — that
                needs a billing table with real invoices, which this platform does not have yet.
            </p>
        </div>
    );
}
