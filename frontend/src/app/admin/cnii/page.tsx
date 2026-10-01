'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { Shield, Search, Loader2, CheckCircle2, AlertTriangle, ChevronDown, ChevronUp, ExternalLink, Activity, Bug, Server, TrendingUp, RefreshCw, PlugZap } from 'lucide-react';
import Link from 'next/link';
import { apiUrl, apiFetch } from '@/lib/api';
import { CNII_SECTORS, SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { fetchFeed, timeAgo, SEV_DOT, SEV_BADGE, riskColor } from '@/lib/cnii-types';
import type { CniiAsset, CniiAlert, CniiVuln, ScanResult, Feed } from '@/lib/cnii-types';

// Assets, alerts, vulns and the scanner come from the backend's /api/cnii routes. Each feed is
// shown as "not connected" until the backend serves it — never as zero or as sample data.

function NotConnected({ what, reason }: { what: string; reason: string }) {
  return (
    <div className="text-sm text-[#7A8099] py-6 text-center">
      <PlugZap className="w-4 h-4 inline-block mr-1.5 -mt-0.5" />
      {what} not connected
      <div className="text-xs mt-1">{reason}</div>
    </div>
  );
}

const rows = <T,>(f: Feed<T> | null): T[] => (f?.connected ? f.rows : []);

export default function CNIIOverviewPage() {
  const [assetsFeed, setAssetsFeed] = useState<Feed<CniiAsset> | null>(null);
  const [alertsFeed, setAlertsFeed] = useState<Feed<CniiAlert> | null>(null);
  const [vulnsFeed, setVulnsFeed] = useState<Feed<CniiVuln> | null>(null);

  // Scanner state
  const [scanIP, setScanIP] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState('');
  const [scanNotice, setScanNotice] = useState('');
  const [assigning, setAssigning] = useState(false);
  const [assigned, setAssigned] = useState(false);
  const [assignError, setAssignError] = useState('');
  // The analyst's sector choice, pre-filled from the scan's suggestion.
  const [chosenSector, setChosenSector] = useState('');
  const [chosenSubfield, setChosenSubfield] = useState('');

  // UI state
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const scanRef = useRef<HTMLDivElement>(null);

  const fetchAll = useCallback(async () => {
    const [a, al, v] = await Promise.all([
      fetchFeed<CniiAsset>('assets'),
      fetchFeed<CniiAlert>('alerts'),
      fetchFeed<CniiVuln>('vulns'),
    ]);
    setAssetsFeed(a);
    setAlertsFeed(al);
    setVulnsFeed(v);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      fetchFeed<CniiAsset>('assets'),
      fetchFeed<CniiAlert>('alerts'),
      fetchFeed<CniiVuln>('vulns'),
    ]).then(([a, al, v]) => {
      if (!active) return;
      setAssetsFeed(a);
      setAlertsFeed(al);
      setVulnsFeed(v);
    });
    return () => { active = false; };
  }, []);

  const refresh = () => { setRefreshing(true); fetchAll(); };

  const handleScan = async () => {
    if (!scanIP.trim()) return;
    setScanning(true);
    setScanResult(null);
    setScanError('');
    setScanNotice('');
    setAssigned(false);
    setAssignError('');
    try {
      const res = await apiFetch(apiUrl('/api/cnii/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: scanIP.trim() }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        const result = data as ScanResult;
        setScanResult(result);
        setChosenSector(result.suggestedSectorId);
        setChosenSubfield(result.suggestedSubfield);
        setTimeout(() => scanRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
      } else if (res.status === 503 && data?.error === 'not_connected') {
        setScanNotice(data.message ?? 'The scanner is not connected yet.');
      } else if (res.status === 400) {
        setScanError('Enter a valid IPv4 or IPv6 address.');
      } else {
        setScanError(data?.error ? `Scan failed: ${data.error}` : `Scan failed (HTTP ${res.status}).`);
      }
    } catch {
      setScanError('Scan failed: the backend could not be reached.');
    }
    setScanning(false);
  };

  const handleAssign = async () => {
    if (!scanResult || !chosenSector) return;
    setAssigning(true);
    setAssignError('');
    try {
      // The backend stores its own cached copy of this scan (raw data, CVEs, risk score); the
      // scan fields sent here are only used if that cache has expired.
      const res = await apiFetch(apiUrl('/api/cnii/assets'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: scanResult.ip,
          sectorId: chosenSector,
          subfield: chosenSubfield || undefined,
          hostname: scanResult.hostname,
          owner: scanResult.owner,
          org: scanResult.org,
          asn: scanResult.asn,
          country: scanResult.country,
          domains: scanResult.domains,
          subdomains: scanResult.subdomains,
          openPorts: scanResult.openPorts,
        }),
      });
      if (res.ok) {
        setAssigned(true);
        fetchAll();
      } else {
        const d = await res.json().catch(() => null);
        setAssignError(d?.message ?? d?.error ?? `Could not add the asset (HTTP ${res.status}).`);
      }
    } catch {
      setAssignError('Could not add the asset: the backend could not be reached.');
    }
    setAssigning(false);
  };

  const loading = assetsFeed === null;
  const assets = rows(assetsFeed);
  const alerts = rows(alertsFeed);
  const vulns = rows(vulnsFeed);
  const assetsOn = !!assetsFeed?.connected;
  const alertsOn = !!alertsFeed?.connected;
  const vulnsOn = !!vulnsFeed?.connected;

  // Derived stats
  const criticalVulns = vulns.filter(v => v.severity === 'critical').length;
  const sectorCounts = CNII_SECTORS.map(s => ({
    ...s,
    alerts: alerts.filter(a => a.sectorId === s.id).length,
    assets: assets.filter(a => a.sectorId === s.id).length,
    vulns: vulns.filter(v => v.sectorId === s.id).length,
  }));
  const topBy = (key: 'alerts' | 'vulns') => {
    const top = [...sectorCounts].sort((a, b) => b[key] - a[key])[0];
    return top && top[key] > 0 ? top.label : 'None';
  };
  const dash = (on: boolean, v: number | string) => (loading ? '…' : on ? v : '—');

  return (
    <div className="p-4 sm:p-6 space-y-6">

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-[#1C1F2E] flex items-center gap-2">
            <Shield className="w-6 h-6 text-[#2B3BCC]" /> CNII Watch
          </h1>
          <p className="text-[#7A8099] text-sm mt-1">
            Nigeria Critical National Information Infrastructure — 13 sectors · asset monitoring · threat intelligence
          </p>
        </div>
        <button onClick={refresh} className="flex items-center gap-2 text-sm text-[#7A8099] hover:text-[#2B3BCC] transition-colors">
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Assets Monitored',       value: dash(assetsOn, assets.length), color: 'text-[#1C1F2E]', icon: Server },
          { label: 'Active Alerts',          value: dash(alertsOn, alerts.length), color: alerts.length > 0 ? 'text-[#CC2B2B]' : 'text-[#1C1F2E]', icon: Activity },
          { label: 'Vulnerabilities',        value: dash(vulnsOn, vulns.length),   color: vulns.length > 0 ? 'text-amber-600' : 'text-[#1C1F2E]', icon: Bug },
          { label: 'Critical CVEs',          value: dash(vulnsOn, criticalVulns),  color: criticalVulns > 0 ? 'text-[#CC2B2B]' : 'text-[#1C1F2E]', icon: AlertTriangle },
          { label: 'Highest Alert Sector',   value: dash(alertsOn, topBy('alerts')), color: 'text-[#2B3BCC]', icon: TrendingUp, small: true },
          { label: 'Most Vulnerable Sector', value: dash(vulnsOn, topBy('vulns')),   color: 'text-amber-600', icon: Bug, small: true },
        ].map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="bg-white rounded-xl border border-gray-100 p-4">
              <Icon className={`w-4 h-4 mb-2 ${s.color}`} />
              <div className={`font-bold ${s.small ? 'text-sm leading-tight' : 'text-xl'} ${s.color}`}>{s.value}</div>
              <div className="text-xs text-[#7A8099] mt-0.5">{s.label}</div>
            </div>
          );
        })}
      </div>

      {/* IP Scanner */}
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        <h2 className="font-semibold text-[#1C1F2E] mb-1 flex items-center gap-2">
          <Search className="w-4 h-4 text-[#2B3BCC]" /> Asset Scanner
        </h2>
        <p className="text-xs text-[#7A8099] mb-4">
          Enter an IP address to run a SpiderFoot + OpenCTI scan. The result will be auto-classified into the correct CNII sector and sub-entity.
        </p>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={scanIP}
            onChange={e => setScanIP(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
            placeholder="e.g. 197.255.224.1"
            className="flex-1 min-w-0 px-4 py-2.5 text-sm border border-gray-200 rounded-lg focus:outline-none focus:border-[#2B3BCC] font-mono"
          />
          <button
            onClick={handleScan}
            disabled={scanning || !scanIP.trim()}
            className="px-5 py-2.5 bg-[#2B3BCC] text-white text-sm font-semibold rounded-lg hover:bg-[#2330aa] disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-colors"
          >
            {scanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning (up to 3 min)…</> : 'Scan IP'}
          </button>
        </div>

        {scanError && (
          <div className="mt-3 text-sm text-[#CC2B2B] bg-red-50 border border-red-100 rounded-lg px-4 py-2">{scanError}</div>
        )}
        {scanNotice && (
          <div className="mt-3 text-sm text-[#7A8099] bg-gray-50 border border-gray-200 rounded-lg px-4 py-2 flex items-center gap-2">
            <PlugZap className="w-4 h-4 flex-shrink-0" /> Scanner not connected — {scanNotice}
          </div>
        )}

        {/* Scan Result */}
        {scanResult && (
          <div ref={scanRef} className="mt-5 border border-gray-100 rounded-xl overflow-hidden">
            <div className="bg-gray-50 px-5 py-3 flex items-center justify-between gap-3">
              <div className="font-semibold text-[#1C1F2E] font-mono break-all">{scanResult.ip}</div>
              {scanResult.suggestedSectorId && (
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-xs text-[#7A8099]">Classification confidence:</span>
                  <span className={`text-xs font-bold ${scanResult.confidence >= 70 ? 'text-green-600' : 'text-amber-600'}`}>
                    {scanResult.confidence}%
                  </span>
                </div>
              )}
            </div>
            {scanResult.warnings.length > 0 && (
              <div className="px-5 pt-4 space-y-1">
                {scanResult.warnings.map(w => (
                  <div key={w} className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {w}
                  </div>
                ))}
              </div>
            )}
            <div className="p-5 grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-2">
                {[
                  ['Hostname',   scanResult.hostname ?? '—'],
                  ['Owner',      scanResult.owner ?? '—'],
                  ['Org',        scanResult.org ?? '—'],
                  ['ASN',        scanResult.asn ?? '—'],
                  ['Country',    scanResult.country ?? '—'],
                  ['Open Ports', scanResult.openPorts.join(', ') || '—'],
                  ['Domains',    scanResult.domains.join(', ') || '—'],
                ].map(([l, v]) => (
                  <div key={l} className="flex gap-2 text-sm">
                    <span className="text-[#7A8099] w-24 flex-shrink-0">{l}</span>
                    <span className="text-[#1C1F2E] font-medium break-all">{v}</span>
                  </div>
                ))}
              </div>
              <div className="space-y-3">
                {/* Classification — suggested by the scan, confirmed (or chosen) by the analyst */}
                <div className="bg-[#2B3BCC]/5 border border-[#2B3BCC]/15 rounded-lg p-4 space-y-2">
                  <div className="text-xs font-semibold text-[#2B3BCC] uppercase tracking-wide">
                    {scanResult.suggestedSectorId ? 'Suggested Classification' : 'Unclassified — choose a sector'}
                  </div>
                  <select
                    value={chosenSector}
                    onChange={e => { setChosenSector(e.target.value); setChosenSubfield(''); }}
                    disabled={assigned}
                    className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white text-[#1C1F2E] focus:outline-none focus:border-[#2B3BCC]"
                  >
                    <option value="">Choose a CNII sector…</option>
                    {CNII_SECTORS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
                  </select>
                  {chosenSector && (
                    <select
                      value={chosenSubfield}
                      onChange={e => setChosenSubfield(e.target.value)}
                      disabled={assigned}
                      className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white text-[#1C1F2E] focus:outline-none focus:border-[#2B3BCC]"
                    >
                      <option value="">Sub-entity (optional)</option>
                      {SECTOR_BY_ID[chosenSector]?.subfields.map(sf => <option key={sf} value={sf}>{sf}</option>)}
                    </select>
                  )}
                </div>

                {/* Vulns found */}
                <div>
                  <div className="text-xs font-semibold text-[#7A8099] uppercase tracking-wide mb-2">Vulnerabilities Found</div>
                  {scanResult.vulns.length === 0 ? (
                    <div className="text-xs text-[#7A8099]">No CVEs reported by this scan.</div>
                  ) : scanResult.vulns.map(v => (
                    <div key={v.cve} className="flex items-center justify-between gap-2 text-xs py-1.5 border-b border-gray-100 last:border-0">
                      <span className="font-mono text-[#CC2B2B]">{v.cve}</span>
                      <span className={`px-2 py-0.5 rounded-full border ${SEV_BADGE[v.severity]}`}>{v.severity.toUpperCase()}</span>
                      <span className="font-bold text-[#1C1F2E] whitespace-nowrap">{v.cvss !== null ? `CVSS ${v.cvss}` : 'CVSS n/a'}</span>
                    </div>
                  ))}
                </div>

                {/* Threat intel */}
                {scanResult.threatIntel.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold text-[#7A8099] uppercase tracking-wide mb-2">Threat Intelligence</div>
                    {scanResult.threatIntel.map((t, i) => (
                      <div key={i} className={`text-xs px-3 py-2 rounded-lg mb-1 border ${SEV_BADGE[t.severity] ?? SEV_BADGE.medium}`}>
                        <span className="font-bold">{t.source}:</span> {t.description}
                      </div>
                    ))}
                  </div>
                )}

                {/* Assign button */}
                {!assigned ? (
                  <>
                    <button
                      onClick={handleAssign}
                      disabled={assigning || !chosenSector}
                      className="w-full py-2.5 bg-[#1C1F2E] text-white text-sm font-semibold rounded-lg hover:bg-black disabled:opacity-50 flex items-center justify-center gap-2 transition-colors"
                    >
                      {assigning ? <><Loader2 className="w-4 h-4 animate-spin" /> Assigning...</> : 'Add to CNII Monitoring'}
                    </button>
                    {assignError && <div className="text-xs text-[#CC2B2B]">{assignError}</div>}
                  </>
                ) : (
                  <div className="w-full py-2.5 bg-green-50 border border-green-200 text-green-700 text-sm font-semibold rounded-lg flex items-center justify-center gap-2">
                    <CheckCircle2 className="w-4 h-4" /> Asset added to monitoring
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Recent Alerts */}
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        <h2 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#CC2B2B]" /> Recent Alerts Across All CNII
        </h2>
        {alertsFeed === null ? <div className="text-sm text-[#7A8099]">Loading...</div> :
          !alertsFeed.connected ? <NotConnected what="Alert feed" reason={alertsFeed.reason} /> :
          alerts.length === 0 ? <div className="text-sm text-[#7A8099] py-4 text-center">No active alerts</div> :
          <div className="space-y-2">
            {alerts.slice(0, 6).map(alert => (
              <div key={alert.id} className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[alert.severity]}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-[#1C1F2E] truncate">{alert.title}</div>
                  <div className="text-xs text-[#7A8099] truncate">
                    {alert.ip} · {SECTOR_BY_ID[alert.sectorId]?.label ?? alert.sectorId} · {alert.source.toUpperCase()}
                  </div>
                </div>
                <span className="text-xs text-[#7A8099] flex-shrink-0">{timeAgo(alert.timestamp)}</span>
              </div>
            ))}
          </div>
        }
      </div>

      {/* Vulnerabilities */}
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        <h2 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
          <Bug className="w-4 h-4 text-amber-600" /> Vulnerabilities Across CNII
        </h2>
        {vulnsFeed === null ? <div className="text-sm text-[#7A8099]">Loading...</div> :
          !vulnsFeed.connected ? <NotConnected what="Vulnerability feed" reason={vulnsFeed.reason} /> :
          vulns.length === 0 ? <div className="text-sm text-[#7A8099] py-4 text-center">No open vulnerabilities</div> :
          <div className="space-y-2">
            {vulns.map(vuln => (
              <div key={vuln.id} className={`border rounded-xl overflow-hidden ${vuln.severity === 'critical' ? 'border-red-200' : 'border-gray-100'}`}>
                <button
                  className="w-full text-left p-4 flex items-center gap-3"
                  onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                >
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[vuln.severity]}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono font-bold text-[#2B3BCC]">{vuln.cve}</span>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${SEV_BADGE[vuln.severity]}`}>
                        {vuln.severity.toUpperCase()} · {vuln.cvss}
                      </span>
                      <span className="text-xs text-[#7A8099]">{SECTOR_BY_ID[vuln.sectorId]?.label ?? vuln.sectorId}</span>
                    </div>
                    <div className="text-sm font-medium text-[#1C1F2E] mt-0.5">{vuln.title}</div>
                  </div>
                  {expandedVuln === vuln.id ? <ChevronUp className="w-4 h-4 text-[#7A8099]" /> : <ChevronDown className="w-4 h-4 text-[#7A8099]" />}
                </button>
                {expandedVuln === vuln.id && (
                  <div className="px-4 pb-4 border-t border-gray-100 pt-3 space-y-3">
                    <div className="flex flex-wrap gap-x-8 gap-y-1 text-sm">
                      <div><span className="text-[#7A8099]">Asset IP: </span><span className="font-mono font-medium">{vuln.ip}</span></div>
                      <div><span className="text-[#7A8099]">Service: </span><span className="font-medium">{vuln.affectedService ?? '—'}</span></div>
                      <div><span className="text-[#7A8099]">Status: </span><span className="font-medium capitalize">{vuln.status.replace('_', ' ')}</span></div>
                    </div>
                    {vuln.complianceImpact.length > 0 && (
                      <div>
                        <div className="text-xs font-semibold text-[#7A8099] uppercase tracking-wide mb-1">Compliance Impact</div>
                        <div className="flex flex-wrap gap-2">
                          {vuln.complianceImpact.map(c => (
                            <span key={c} className="text-xs bg-amber-50 border border-amber-200 text-amber-700 px-2 py-0.5 rounded-full">{c}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="flex gap-3">
                      <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.cve)}`} target="_blank" rel="noopener noreferrer"
                        className="text-xs text-[#2B3BCC] flex items-center gap-1 hover:underline">
                        <ExternalLink className="w-3 h-3" /> NVD
                      </a>
                      <Link href={`/admin/cnii/ip/${encodeURIComponent(vuln.ip)}`} className="text-xs text-[#2B3BCC] flex items-center gap-1 hover:underline">
                        Deep Investigation →
                      </Link>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        }
      </div>

      {/* Sector cards — 3 per row */}
      <div>
        <h2 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-[#2B3BCC]" /> Sectors
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {sectorCounts.map(sector => {
            const Icon = sector.icon;
            return (
              <Link key={sector.id} href={`/admin/cnii/${sector.id}`}
                className="bg-white rounded-xl border border-gray-100 p-5 hover:shadow-md hover:border-[#2B3BCC]/20 transition-all group block">
                <div className="flex items-start justify-between mb-3">
                  <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${sector.color}18` }}>
                    <Icon className="w-4 h-4" style={{ color: sector.color }} />
                  </div>
                  {sector.alerts > 0 && (
                    <span className="text-xs font-bold text-[#CC2B2B] bg-red-50 px-2 py-0.5 rounded-full flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse inline-block" />
                      {sector.alerts} alert{sector.alerts !== 1 ? 's' : ''}
                    </span>
                  )}
                </div>
                <div className="font-semibold text-[#1C1F2E] group-hover:text-[#2B3BCC] transition-colors mb-1">{sector.label}</div>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#7A8099] mb-3">
                  <span>{assetsOn ? `${sector.assets} asset${sector.assets !== 1 ? 's' : ''}` : 'Assets —'}</span>
                  <span>{vulnsOn ? `${sector.vulns} vuln${sector.vulns !== 1 ? 's' : ''}` : 'Vulns —'}</span>
                  <span>{sector.subfields.length} sub-entities</span>
                </div>
                {alertsOn ? (
                  <div className="w-full bg-gray-100 rounded-full h-1.5">
                    <div className="h-1.5 rounded-full transition-all"
                      style={{ width: `${Math.min((sector.alerts / 10) * 100, 100)}%`, backgroundColor: sector.alerts > 5 ? '#CC2B2B' : sector.alerts > 0 ? '#F59E0B' : '#10B981' }} />
                  </div>
                ) : (
                  <div className="text-xs text-[#7A8099]">{alertsFeed === null ? 'Checking alert feed…' : 'Alerts not connected'}</div>
                )}
              </Link>
            );
          })}
        </div>
      </div>

      {/* Assets table */}
      <div className="bg-white rounded-xl border border-gray-100 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="font-semibold text-[#1C1F2E] flex items-center gap-2">
            <Server className="w-4 h-4 text-[#2B3BCC]" /> Monitored Assets
          </h2>
          {assetsOn && <span className="text-xs text-[#7A8099]">{assets.length} total</span>}
        </div>
        {assetsFeed === null ? <div className="text-sm text-[#7A8099] p-5">Loading...</div> :
          !assetsFeed.connected ? <NotConnected what="Asset inventory" reason={assetsFeed.reason} /> :
          assets.length === 0 ? <div className="text-sm text-[#7A8099] py-6 text-center">No assets under monitoring yet — scan an IP above to add one.</div> :
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100">
                  {['IP Address', 'Sector', 'Sub-entity', 'Owner', 'Domains', 'Alerts', 'Vulns', 'Risk', ''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-[#7A8099] uppercase tracking-wide whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {assets.map(asset => (
                  <tr key={asset.id} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-[#2B3BCC] font-bold">{asset.ip}</td>
                    <td className="px-4 py-3 text-xs text-[#1C1F2E]">{SECTOR_BY_ID[asset.sectorId]?.label ?? asset.sectorId}</td>
                    <td className="px-4 py-3 text-xs text-[#7A8099]">{asset.subfield ?? '—'}</td>
                    <td className="px-4 py-3 text-xs text-[#1C1F2E]">{asset.owner ?? '—'}</td>
                    <td className="px-4 py-3 text-xs text-[#7A8099] max-w-32 truncate">{asset.domains.join(', ') || '—'}</td>
                    <td className="px-4 py-3 text-xs font-bold text-[#CC2B2B]">{alertsOn ? alerts.filter(a => a.ip === asset.ip).length : '—'}</td>
                    <td className="px-4 py-3 text-xs font-bold text-amber-600">{vulnsOn ? vulns.filter(v => v.ip === asset.ip).length : '—'}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-100 rounded-full h-1.5">
                          <div className="h-1.5 rounded-full" style={{ width: `${asset.riskScore}%`, backgroundColor: riskColor(asset.riskScore) }} />
                        </div>
                        <span className="text-xs text-[#7A8099]">{asset.riskScore}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Link href={`/admin/cnii/ip/${encodeURIComponent(asset.ip)}`} className="text-xs text-[#2B3BCC] hover:underline whitespace-nowrap">
                        Investigate →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        }
      </div>

      {/* Footer note */}
      <div className="bg-[#2B3BCC]/5 border border-[#2B3BCC]/10 rounded-xl p-4 text-sm text-[#7A8099] leading-relaxed">
        <span className="font-medium text-[#1C1F2E]">Legal basis: </span>
        Nigeria CNII sectors are designated under the Cybercrimes (Prohibition, Prevention, etc.) Act 2015 and
        the National Cybersecurity Policy & Strategy (NCPS) 2021.
      </div>

    </div>
  );
}
