'use client';

import { useParams } from 'next/navigation';
import { useState, useEffect } from 'react';
import { ArrowLeft, Server, Shield, Bug, Activity, AlertTriangle, ExternalLink, Globe, Network, Lock, PlugZap } from 'lucide-react';
import Link from 'next/link';
import { SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { fetchFeed, timeAgo, SEV_DOT, SEV_BADGE, riskColor } from '@/lib/cnii-types';
import type { CniiAsset, CniiAlert, CniiVuln, Feed } from '@/lib/cnii-types';

// Deep investigation for one IP: its asset record, alerts and vulns from the /api/cnii feeds
// (filtered by ?ip=), plus links out to public intel sources. The external links work for any
// IP, so they are shown even while the CNII feeds are not connected.

interface Loaded {
  ip: string;
  assets: Feed<CniiAsset>;
  alerts: Feed<CniiAlert>;
  vulns: Feed<CniiVuln>;
}

function NotConnected({ what, reason }: { what: string; reason: string }) {
  return (
    <div className="text-sm text-[#7A8099] py-4 text-center">
      <PlugZap className="w-4 h-4 inline-block mr-1.5 -mt-0.5" />
      {what} not connected
      <div className="text-xs mt-1">{reason}</div>
    </div>
  );
}

function ExternalIntel({ ip }: { ip: string }) {
  const q = encodeURIComponent(ip);
  return (
    <div className="bg-white rounded-xl border border-gray-100 p-5">
      <h3 className="font-semibold text-[#1C1F2E] mb-3 flex items-center gap-2">
        <Network className="w-4 h-4 text-[#2B3BCC]" /> External Intelligence
      </h3>
      <div className="flex flex-wrap gap-3">
        {[
          { label: 'Shodan',     url: `https://www.shodan.io/host/${q}` },
          { label: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${q}` },
          { label: 'AbuseIPDB',  url: `https://www.abuseipdb.com/check/${q}` },
          { label: 'Censys',     url: `https://search.censys.io/hosts/${q}` },
          { label: 'BGP View',   url: `https://bgpview.io/ip/${q}` },
        ].map(link => (
          <a key={link.label} href={link.url} target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-sm text-[#2B3BCC] bg-[#2B3BCC]/5 border border-[#2B3BCC]/15 px-3 py-1.5 rounded-lg hover:bg-[#2B3BCC]/10 transition-colors">
            <ExternalLink className="w-3 h-3" /> {link.label}
          </a>
        ))}
      </div>
    </div>
  );
}

export default function IPInvestigationPage() {
  const params = useParams();
  const ip = decodeURIComponent(params.ip as string);
  const [loaded, setLoaded] = useState<Loaded | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([
      fetchFeed<CniiAsset>('assets', { ip }),
      fetchFeed<CniiAlert>('alerts', { ip }),
      fetchFeed<CniiVuln>('vulns', { ip }),
    ]).then(([assets, alerts, vulns]) => {
      if (active) setLoaded({ ip, assets, alerts, vulns });
    });
    return () => { active = false; };
  }, [ip]);

  const back = (
    <Link href="/admin/cnii" className="text-sm text-[#7A8099] hover:text-[#2B3BCC] flex items-center gap-1 mb-3 w-fit">
      <ArrowLeft className="w-3 h-3" /> CNII Watch
    </Link>
  );

  const current = loaded?.ip === ip ? loaded : null;
  if (!current) return <div className="p-6 text-sm text-[#7A8099]">Loading...</div>;

  // Asset inventory unavailable or IP not in it: say which, and still offer external intel.
  const asset = current.assets.connected ? current.assets.rows.find(a => a.ip === ip) ?? null : null;
  if (!asset) return (
    <div className="p-4 sm:p-6 space-y-6">
      <div>
        {back}
        <h1 className="text-2xl font-bold text-[#1C1F2E] font-mono break-all">{ip}</h1>
      </div>
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        {!current.assets.connected
          ? <NotConnected what="Asset inventory" reason={current.assets.reason} />
          : <p className="text-sm text-[#7A8099]">Asset <span className="font-mono">{ip}</span> is not in CNII monitoring.</p>}
      </div>
      <ExternalIntel ip={ip} />
    </div>
  );

  const alerts = current.alerts.connected ? current.alerts.rows.filter(a => a.ip === ip) : [];
  const vulns = current.vulns.connected ? current.vulns.rows.filter(v => v.ip === ip) : [];
  const sector = SECTOR_BY_ID[asset.sectorId];
  const criticalVulns = vulns.filter(v => v.severity === 'critical').length;
  const complianceHits = [...new Set(vulns.flatMap(v => v.complianceImpact))];
  const show = (on: boolean, n: number) => (on ? n : '—');

  return (
    <div className="p-4 sm:p-6 space-y-6">

      {/* Back + Header */}
      <div>
        {back}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-2xl font-bold text-[#1C1F2E] font-mono break-all">{asset.ip}</h1>
            <p className="text-[#7A8099] text-sm mt-1">{[asset.hostname, asset.org, asset.asn].filter(Boolean).join(' · ') || '—'}</p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-black" style={{ color: riskColor(asset.riskScore) }}>{asset.riskScore}</div>
            <div className="text-xs text-[#7A8099]">Risk Score</div>
          </div>
        </div>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Active Alerts',     value: show(current.alerts.connected, alerts.length), color: alerts.length > 0 ? 'text-[#CC2B2B]' : 'text-[#1C1F2E]', icon: Activity },
          { label: 'Vulnerabilities',   value: show(current.vulns.connected, vulns.length),   color: vulns.length > 0 ? 'text-amber-600' : 'text-[#1C1F2E]', icon: Bug },
          { label: 'Critical CVEs',     value: show(current.vulns.connected, criticalVulns),  color: criticalVulns > 0 ? 'text-[#CC2B2B]' : 'text-[#1C1F2E]', icon: AlertTriangle },
          { label: 'Compliance Issues', value: show(current.vulns.connected, complianceHits.length), color: complianceHits.length > 0 ? 'text-amber-600' : 'text-[#1C1F2E]', icon: Lock },
        ].map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="bg-white rounded-xl border border-gray-100 p-4 flex items-center gap-3">
              <Icon className={`w-5 h-5 flex-shrink-0 ${s.color}`} />
              <div>
                <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-[#7A8099]">{s.label}</div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Asset Profile */}
        <div className="bg-white rounded-xl border border-gray-100 p-5">
          <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
            <Server className="w-4 h-4 text-[#2B3BCC]" /> Asset Profile
          </h3>
          <div className="space-y-2.5">
            {[
              ['IP',           asset.ip],
              ['Hostname',     asset.hostname ?? '—'],
              ['Owner',        asset.owner ?? '—'],
              ['Organisation', asset.org ?? '—'],
              ['ASN',          asset.asn ?? '—'],
              ['Country',      asset.country ?? '—'],
              ['CNII Sector',  sector?.label ?? '—'],
              ['Sub-entity',   asset.subfield ?? '—'],
              ['Open Ports',   asset.openPorts.join(', ') || '—'],
              ['Last Seen',    timeAgo(asset.lastSeen)],
              ['Added',        timeAgo(asset.addedAt)],
            ].map(([l, v]) => (
              <div key={l} className="flex gap-2 text-sm">
                <span className="text-[#7A8099] w-32 flex-shrink-0">{l}</span>
                <span className="text-[#1C1F2E] font-medium break-all">{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Domains + Compliance */}
        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="font-semibold text-[#1C1F2E] mb-3 flex items-center gap-2">
              <Globe className="w-4 h-4 text-[#2B3BCC]" /> Domains & Subdomains
            </h3>
            <div className="flex flex-wrap gap-2">
              {[...asset.domains, ...asset.subdomains].map(d => (
                <span key={d} className="text-xs font-mono bg-gray-50 border border-gray-200 text-[#1C1F2E] px-2 py-1 rounded break-all">{d}</span>
              ))}
              {asset.domains.length === 0 && asset.subdomains.length === 0 && (
                <span className="text-xs text-[#7A8099]">No domains found</span>
              )}
            </div>
          </div>

          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="font-semibold text-[#1C1F2E] mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#2B3BCC]" /> CNII Classification
            </h3>
            {sector && (
              <div className="mb-3 p-3 rounded-lg border" style={{ backgroundColor: `${sector.color}10`, borderColor: `${sector.color}30` }}>
                <div className="font-semibold text-sm" style={{ color: sector.color }}>{sector.label}</div>
                {asset.subfield && <div className="text-xs text-[#7A8099] mt-0.5">{asset.subfield}</div>}
              </div>
            )}
            <div className="text-xs font-semibold text-[#7A8099] uppercase tracking-wide mb-2">Applicable Compliance Frameworks</div>
            <div className="flex flex-wrap gap-2">
              {sector?.compliance.map(c => (
                <span key={c} className="text-xs bg-[#2B3BCC]/10 text-[#2B3BCC] border border-[#2B3BCC]/20 px-2 py-0.5 rounded-full">{c}</span>
              ))}
            </div>
            {complianceHits.length > 0 && (
              <>
                <div className="text-xs font-semibold text-amber-700 uppercase tracking-wide mb-2 mt-3">Violated by Current Vulns</div>
                <div className="flex flex-wrap gap-2">
                  {complianceHits.map(c => (
                    <span key={c} className="text-xs bg-amber-50 border border-amber-200 text-amber-700 px-2 py-0.5 rounded-full">{c}</span>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Alerts for this IP */}
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#CC2B2B]" /> Alerts for this Asset
        </h3>
        {!current.alerts.connected ? (
          <NotConnected what="Alert feed" reason={current.alerts.reason} />
        ) : alerts.length === 0 ? (
          <div className="text-sm text-[#7A8099] py-4 text-center">No alerts for this IP</div>
        ) : (
          <div className="space-y-2">
            {alerts.map(alert => (
              <div key={alert.id} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                <span className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${SEV_DOT[alert.severity]}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-[#1C1F2E]">{alert.title}</div>
                  <div className="text-xs text-[#7A8099]">Source: {alert.source.toUpperCase()} · {timeAgo(alert.timestamp)}</div>
                </div>
                <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${SEV_BADGE[alert.severity]}`}>
                  {alert.severity.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Vulns for this IP */}
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
          <Bug className="w-4 h-4 text-amber-600" /> Vulnerabilities on this Asset
        </h3>
        {!current.vulns.connected ? (
          <NotConnected what="Vulnerability feed" reason={current.vulns.reason} />
        ) : vulns.length === 0 ? (
          <div className="text-sm text-[#7A8099] py-4 text-center">No vulnerabilities detected</div>
        ) : (
          <div className="space-y-3">
            {vulns.map(vuln => (
              <div key={vuln.id} className={`border rounded-xl p-4 ${vuln.severity === 'critical' ? 'border-red-200 bg-red-50/30' : 'border-gray-100'}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-bold text-[#2B3BCC]">{vuln.cve}</span>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${SEV_BADGE[vuln.severity]}`}>
                        {vuln.severity.toUpperCase()} · CVSS {vuln.cvss}
                      </span>
                    </div>
                    <div className="text-sm font-medium text-[#1C1F2E]">{vuln.title}</div>
                    {vuln.affectedService && <div className="text-xs text-[#7A8099] mt-0.5">{vuln.affectedService}</div>}
                  </div>
                  <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.cve)}`} target="_blank" rel="noopener noreferrer"
                    className="text-xs text-[#2B3BCC] flex items-center gap-1 hover:underline flex-shrink-0">
                    <ExternalLink className="w-3 h-3" /> NVD
                  </a>
                </div>
                {vuln.complianceImpact.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-3">
                    {vuln.complianceImpact.map(c => (
                      <span key={c} className="text-xs bg-amber-50 border border-amber-200 text-amber-700 px-2 py-0.5 rounded-full">{c}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <ExternalIntel ip={asset.ip} />

    </div>
  );
}
