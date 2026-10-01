// Shapes returned by the backend's /api/cnii routes (backend/src/routes/cnii.ts), plus the
// client helpers every CNII page uses to call them.
import { apiUrl, apiFetch } from './api';

export interface CniiAsset {
  id: string;
  ip: string;
  hostname?: string;
  owner?: string;
  org?: string;
  asn?: string;
  country?: string;
  sectorId: string;
  subfield?: string;
  domains: string[];
  subdomains: string[];
  openPorts: number[];
  alertCount: number;
  vulnCount: number;
  lastSeen: string;
  addedAt: string;
  scanStatus: 'pending' | 'scanning' | 'done' | 'failed';
  riskScore: number; // 0-100
}

export interface CniiAlert {
  id: string;
  ip: string;
  sectorId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: string;
  source: 'wazuh' | 'spiderfoot' | 'opencti';
}

export interface CniiVuln {
  id: string;
  ip: string;
  sectorId: string;
  cve: string;
  title: string;
  cvss: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  affectedService?: string;
  complianceImpact: string[];
  status: 'open' | 'in_progress' | 'patched';
  discoveredAt: string;
  source?: 'spiderfoot' | 'wazuh';
}

export interface ScanResult {
  ip: string;
  hostname?: string;
  owner?: string;
  org?: string;
  asn?: string;
  country?: string;
  domains: string[];
  subdomains: string[];
  openPorts: number[];
  vulns: { cve: string; cvss: number | null; severity: 'critical' | 'high' | 'medium' | 'low'; service?: string }[];
  threatIntel: { source: string; description: string; severity: string }[];
  suggestedSectorId: string; // '' when no sector matched — the analyst must choose
  suggestedSubfield: string;
  confidence: number; // 0-100
  warnings: string[]; // e.g. OpenCTI unavailable — the result is partial
  rawSpiderfoot: Record<string, unknown>;
  rawOpencti: Record<string, unknown>;
}

// A feed is either connected (with its rows) or not, with the backend's reason. Pages show
// "not connected" for the latter rather than an empty list that reads as "nothing found".
export type Feed<T> = { connected: true; rows: T[] } | { connected: false; reason: string };

export async function fetchFeed<T>(feed: 'assets' | 'alerts' | 'vulns', filter: { sector?: string; ip?: string } = {}): Promise<Feed<T>> {
  const qs = new URLSearchParams(Object.entries(filter).filter(([, v]) => v) as [string, string][]).toString();
  try {
    const r = await apiFetch(apiUrl(`/api/cnii/${feed}${qs ? `?${qs}` : ''}`), { cache: 'no-store' });
    const d = await r.json().catch(() => null);
    if (r.ok && Array.isArray(d)) return { connected: true, rows: d as T[] };
    return { connected: false, reason: typeof d?.message === 'string' ? d.message : typeof d?.error === 'string' ? d.error : `HTTP ${r.status}` };
  } catch {
    return { connected: false, reason: 'Backend unreachable' };
  }
}

export function timeAgo(iso: string) {
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

export const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-amber-500', medium: 'bg-blue-400', low: 'bg-gray-400',
};

export const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-50 text-[#CC2B2B] border-red-200',
  high:     'bg-amber-50 text-amber-700 border-amber-200',
  medium:   'bg-blue-50 text-[#2B3BCC] border-blue-200',
  low:      'bg-gray-50 text-[#7A8099] border-gray-200',
};

export const riskColor = (score: number) => (score >= 75 ? '#CC2B2B' : score >= 50 ? '#F59E0B' : '#10B981');
