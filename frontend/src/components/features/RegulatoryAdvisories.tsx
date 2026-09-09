'use client';

import { useState } from 'react';
import { ExternalLink, AlertTriangle, Info } from 'lucide-react';

// Shared renderer for the CBN and NCC advisory pages — the two differ only in their content and
// their sector list, so this holds the layout, the sector/severity filtering and, importantly,
// the provenance banner.
//
// PROVENANCE: these entries are illustrative reference content, not scraped bulletins. Neither
// regulator publishes a machine-readable advisory feed this backend can consume (cert.gov.ng
// returns 403 to Railway's egress — see services/nigerianIntelCollector.ts), so there is no live
// source behind these pages yet. Every item is therefore marked, and each links to the
// regulator's real publication index so an analyst can check the actual circulars rather than
// treating this page as authoritative. No CVE identifiers are invented here for the same reason.

export interface RegulatoryAdvisory {
    id: string;
    title: string;
    date: string;
    severity: 'critical' | 'high' | 'medium' | 'policy';
    category: string;
    sector: string;
    summary: string;
    url: string;
    tags: string[];
}

const SEVERITY_STYLE: Record<RegulatoryAdvisory['severity'], string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-amber/10 text-amber border-amber/30',
    medium: 'bg-blue/10 text-blue border-blue/30',
    policy: 'bg-purple/10 text-purple border-purple/30',
};

export function RegulatoryAdvisories({
    title,
    subtitle,
    issuer,
    issuerUrl,
    advisories,
    sectors,
}: {
    title: string;
    subtitle: string;
    issuer: string;
    issuerUrl: string;
    advisories: RegulatoryAdvisory[];
    sectors: string[];
}) {
    const [sector, setSector] = useState('All Sectors');
    const [severity, setSeverity] = useState<'all' | RegulatoryAdvisory['severity']>('all');

    const filtered = advisories.filter((a) => {
        if (sector !== 'All Sectors' && a.sector !== sector) return false;
        if (severity !== 'all' && a.severity !== severity) return false;
        return true;
    });

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">{title}</h1>
                <p className="text-xs text-foreground-muted">{subtitle}</p>
            </div>

            {/* Provenance — stated up front, not buried at the bottom. */}
            <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3">
                <Info size={16} className="text-amber-700 shrink-0 mt-0.5" />
                <div>
                    <p className="text-sm text-amber-800 font-medium">Reference content, not a live feed</p>
                    <p className="text-xs text-amber-700 mt-1">
                        {issuer} does not publish a machine-readable advisory feed, so these entries are illustrative
                        summaries of the kinds of guidance it issues — not scraped bulletins, and not verbatim text.
                        Always confirm against the official publication index before acting or citing.{' '}
                        <a href={issuerUrl} target="_blank" rel="noopener noreferrer" className="font-bold underline">
                            Open {issuer} publications
                        </a>
                    </p>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                <div>
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Sector</p>
                    <div className="flex gap-2 flex-wrap">
                        {sectors.map((s) => (
                            <button
                                key={s}
                                onClick={() => setSector(s)}
                                className={`text-xs px-3 py-1.5 rounded-full font-medium transition-colors ${
                                    sector === s ? 'bg-purple text-white' : 'bg-card-muted text-foreground-muted hover:text-purple'
                                }`}
                            >
                                {s}
                            </button>
                        ))}
                    </div>
                </div>
                <div>
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Severity</p>
                    <div className="flex gap-2 flex-wrap">
                        {(['all', 'critical', 'high', 'medium', 'policy'] as const).map((s) => (
                            <button
                                key={s}
                                onClick={() => setSeverity(s)}
                                className={`text-xs px-3 py-1.5 rounded-full font-medium uppercase transition-colors ${
                                    severity === s ? 'bg-purple text-white' : 'bg-card-muted text-foreground-muted hover:text-purple'
                                }`}
                            >
                                {s === 'all' ? 'All' : s}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            <p className="text-[11px] text-foreground-muted">
                Showing {filtered.length} of {advisories.length} advisories
            </p>

            {filtered.length === 0 ? (
                <div className="bg-card border border-dashed border-grey-300 rounded-xl p-10 text-center">
                    <AlertTriangle size={28} className="text-border mx-auto mb-2" />
                    <p className="text-xs text-foreground-muted">No advisories match these filters.</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {filtered.map((a) => (
                        <div key={a.id} className="bg-card border border-border rounded-xl p-4">
                            <div className="flex items-start justify-between gap-3 flex-wrap mb-2">
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${SEVERITY_STYLE[a.severity]}`}>
                                        {a.severity}
                                    </span>
                                    <span className="text-[10px] font-medium px-2 py-0.5 bg-card-muted text-foreground-muted rounded-full">
                                        {a.category}
                                    </span>
                                    <span className="font-mono text-[10px] text-foreground-muted">{a.id}</span>
                                </div>
                                <span className="text-[10px] text-foreground-muted shrink-0">{a.date}</span>
                            </div>

                            <p className="text-sm font-bold text-foreground mb-1">{a.title}</p>
                            <p className="text-xs text-foreground-muted mb-3">{a.summary}</p>

                            <div className="flex items-center justify-between gap-3 flex-wrap">
                                <div className="flex flex-wrap gap-1">
                                    {a.tags.map((t) => (
                                        <span key={t} className="text-[9px] font-medium px-1.5 py-0.5 bg-card-muted text-foreground-muted rounded-full">
                                            {t}
                                        </span>
                                    ))}
                                </div>
                                <a
                                    href={a.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-[11px] text-blue hover:text-purple font-bold flex items-center gap-1 shrink-0"
                                >
                                    View official publications <ExternalLink size={11} />
                                </a>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
