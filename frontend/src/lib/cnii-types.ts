// Shapes returned by the backend's /api/cnii routes (backend/src/routes/cnii.ts, phase P9) and
// helpers for the CNII Watch pages. CNII Watch is a sector view over VMS and the Threat
// Information System: every figure comes from those records, and a page that cannot load says so.

import { apiUrl, apiFetch } from './api';
import { loadJson, type Loaded } from './alerts';

export interface CniiProfile {
    org_id: string; sector_id: string; subfield: string | null; designation: 'designated' | 'candidate';
    designation_reference: string | null; notes: string | null; created_by: string; created_at: string; updated_by: string; updated_at: string;
}
export interface CniiProfileEvent { id: string; at: string; actor: string; from_value: Partial<CniiProfile> | null; to_value: Partial<CniiProfile> }
export interface OrgStats {
    assets: number; probable_assets: number; internet_facing: number;
    open_findings: { P1: number; P2: number; P3: number; P4: number };
    confirmed_p1_p2: number; unconfirmed_open: number; kev_open: number; new_matches: number;
    active_scopes: number; passive_only_scopes: number; scope_expires_next: string | null;
    last_collection: { at: string; status: string } | null;
}
export interface SectorSummary {
    id: string; organisations: number; designated: number; unmonitored: number; with_gaps: number;
    assets: number; probable_assets: number; internet_facing: number; open_findings: OrgStats['open_findings'];
    confirmed_p1_p2: number; unconfirmed_open: number; kev_open: number; new_matches: number;
}
export interface CniiScope {
    id: string; kind: 'domain' | 'ip' | 'cidr' | 'asn'; value: string; include_subdomains: boolean; allow_discovery?: boolean;
    allow_port_scan: boolean; allow_vuln_scan: boolean; authorization_reference: string; status: 'active' | 'revoked';
    approved_by: string; approved_at: string; expires_at: string; notes: string | null;
}
export interface Authorisation {
    status: 'authorised' | 'expired' | 'revoked' | 'not_authorised'; scope_id: string | null; scope: string | null; expires_at: string | null;
    passive: boolean; discovery: boolean; ports: boolean; vuln: boolean;
}
export interface CniiAsset {
    id: string; asset_type: 'domain' | 'host' | 'ip' | 'endpoint' | 'asn' | 'cidr'; value: string; ips: string[]; exposure: 'internet' | 'internal' | 'unknown';
    confidence: 'confirmed' | 'probable'; criticality: string; discovery_sources: string[]; first_seen: string; last_seen: string; status: 'active' | 'gone';
    authorisation: Authorisation; observations: Record<string, number>;
    findings: { open: number; confirmed: number; unconfirmed: number; p1_p2: number }; indicator_matches: number;
}
export interface CniiObservation { id: string; source: string; kind: string; key: string; value: Record<string, unknown>; confidence: 'high' | 'medium' | 'low'; first_seen: string; last_seen: string; seen_count: number }
export interface CniiFinding {
    id: string; title: string; priority: string | null; risk_score: number | null; risk_factors: Record<string, unknown>; status: string;
    evidence_class: EvidenceClass; source_class: string; detected_by: string[]; cve_ids: string[]; port: number | null; first_seen: string; last_seen: string; due_at: string | null; case_id: string | null;
}
export type EvidenceClass = 'scanner_check' | 'package_inventory' | 'version_match' | 'exposure' | 'intelligence';

export const EVIDENCE_LABEL: Record<EvidenceClass, string> = {
    scanner_check: 'Confirmed by scanner check',
    package_inventory: 'Installed package (endpoint agent)',
    version_match: 'Unconfirmed: version match reported by a third party',
    exposure: 'Public exposure',
    intelligence: 'Unconfirmed: third-party intelligence claim',
};
export const isUnconfirmed = (e: EvidenceClass) => e === 'version_match' || e === 'intelligence';

export const AUTH_STYLE: Record<Authorisation['status'], string> = {
    authorised: 'bg-green/10 text-green', expired: 'bg-amber/10 text-amber', revoked: 'bg-red/10 text-red', not_authorised: 'bg-card-muted text-foreground-muted',
};
export const AUTH_LABEL: Record<Authorisation['status'], string> = { authorised: 'Authorised', expired: 'Scope expired', revoked: 'Scope revoked', not_authorised: 'Not authorised' };

/** What an authorised scope entry allows, in words. */
export function permits(a: Pick<Authorisation, 'passive' | 'discovery' | 'ports' | 'vuln'>): string {
    const p = [a.passive && 'passive', a.discovery && 'discovery', a.ports && 'ports', a.vuln && 'vulnerability'].filter(Boolean);
    return p.length ? p.join(' · ') : 'nothing';
}

/** GET from /api/cnii, acting on `org` (staff only: the backend ignores it for client roles and audits it for staff). */
export function cniiGet<T>(path: string, org?: string): Promise<Loaded<T>> {
    return loadJson<T>(`/api/cnii${path}`, org ? { headers: { 'X-Org-Id': org } } : {});
}

/** A write to the API, acting on `org`. Returns the body or the error the backend gave. */
export async function apiSend<T>(path: string, method: 'POST' | 'PUT' | 'PATCH', body: unknown, org?: string): Promise<{ ok: true; data: T } | { ok: false; error: string }> {
    try {
        const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json', ...(org ? { 'X-Org-Id': org } : {}) }, body: JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        return r.ok ? { ok: true, data: d as T } : { ok: false, error: d?.error ?? `HTTP ${r.status}` };
    } catch {
        return { ok: false, error: 'Could not reach the backend' };
    }
}

export function timeAgo(iso: string | null | undefined): string {
    if (!iso) return 'never';
    const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86_400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86_400)}d ago`;
}

export const PRIORITY_STYLE: Record<string, string> = { P1: 'bg-red/10 text-red', P2: 'bg-orange/10 text-orange', P3: 'bg-amber/10 text-amber', P4: 'bg-card-muted text-foreground-muted' };
