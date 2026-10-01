'use client';

import { useParams } from 'next/navigation';
import { useState, useEffect } from 'react';
import { ArrowLeft, Activity, TrendingUp, Bug, Server, Shield, PlugZap } from 'lucide-react';
import Link from 'next/link';
import { SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { fetchFeed, timeAgo, SEV_DOT, SEV_BADGE, riskColor } from '@/lib/cnii-types';
import type { CniiAsset, CniiAlert, CniiVuln, Feed } from '@/lib/cnii-types';

// Sector alerts, vulns and assets come from the backend's /api/cnii feeds filtered by
// ?sector=. A feed that isn't connected is shown as such, never as "no alerts".

// Results for one sector; the page is "loading" whenever they are for a different sector.
interface Loaded {
  sector: string;
  assets: Feed<CniiAsset>;
  alerts: Feed<CniiAlert>;
  vulns: Feed<CniiVuln>;
}

function NotConnected({ what, reason }: { what: string; reason: string }) {
  return (
    <div className="text-sm text-[#7A8099] py-8 text-center">
      <PlugZap className="w-4 h-4 inline-block mr-1.5 -mt-0.5" />
      {what} not connected
      <div className="text-xs mt-1">{reason}</div>
    </div>
  );
}

export default function SectorPage() {
  const params = useParams();
  const sectorId = params.sector as string;
  const meta = SECTOR_BY_ID[sectorId];
  const [loaded, setLoaded] = useState<Loaded | null>(null);

  useEffect(() => {
    if (!SECTOR_BY_ID[sectorId]) return;
    let active = true;
    Promise.all([
      fetchFeed<CniiAsset>('assets', { sector: sectorId }),
      fetchFeed<CniiAlert>('alerts', { sector: sectorId }),
      fetchFeed<CniiVuln>('vulns', { sector: sectorId }),
    ]).then(([assets, alerts, vulns]) => {
      if (active) setLoaded({ sector: sectorId, assets, alerts, vulns });
    });
    return () => { active = false; };
  }, [sectorId]);

  if (!meta) return (
    <div className="p-6">
      <p className="text-[#7A8099] mb-2">Sector not found.</p>
      <Link href="/admin/cnii" className="text-[#2B3BCC] text-sm">← Back to CNII Watch</Link>
    </div>
  );

  const current = loaded?.sector === sectorId ? loaded : null;
  const alerts = current?.alerts.connected ? current.alerts.rows : [];
  const vulns = current?.vulns.connected ? current.vulns.rows : [];
  const assets = current?.assets.connected ? current.assets.rows : [];
  const show = (feed: Feed<unknown> | undefined, n: number) => (!current ? '…' : feed?.connected ? n : '—');
  const Icon = meta.icon;

  return (
    <div className="p-4 sm:p-6 space-y-6">
      {/* Back + Header */}
      <div>
        <Link href="/admin/cnii" className="text-sm text-[#7A8099] hover:text-[#2B3BCC] flex items-center gap-1 mb-3 w-fit">
          <ArrowLeft className="w-3 h-3" /> CNII Watch
        </Link>
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0" style={{ backgroundColor: `${meta.color}18` }}>
            <Icon className="w-6 h-6" style={{ color: meta.color }} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[#1C1F2E]">{meta.label}</h1>
            <p className="text-[#7A8099] text-sm">{meta.description}</p>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Critical Alerts', value: show(current?.alerts, alerts.filter(a => a.severity === 'critical').length), color: 'text-[#CC2B2B]' },
          { label: 'High Alerts',     value: show(current?.alerts, alerts.filter(a => a.severity === 'high').length),     color: 'text-amber-600' },
          { label: 'Open Vulns',      value: show(current?.vulns, vulns.filter(v => v.status !== 'patched').length),     color: 'text-amber-600' },
          { label: 'Assets',          value: show(current?.assets, assets.length),                                         color: 'text-[#1C1F2E]' },
        ].map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-gray-100 p-4">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-sm text-[#7A8099]">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live Alerts */}
        <div className="bg-white rounded-xl border border-gray-100 p-5">
          <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#2B3BCC]" /> Live Alerts
          </h3>
          {!current ? (
            <div className="text-sm text-[#7A8099]">Loading...</div>
          ) : !current.alerts.connected ? (
            <NotConnected what="Sector alert feed" reason={current.alerts.reason} />
          ) : alerts.length === 0 ? (
            <div className="text-sm text-[#7A8099] py-8 text-center">No active alerts for this sector</div>
          ) : (
            <div className="space-y-3">
              {alerts.slice(0, 8).map(alert => (
                <div key={alert.id} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                  <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${SEV_DOT[alert.severity]}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-[#1C1F2E] truncate">{alert.title}</div>
                    <div className="text-xs text-[#7A8099]">{alert.ip} · {alert.source.toUpperCase()} · {timeAgo(alert.timestamp)}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-4">
          {/* Sub-entity Cards */}
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="font-semibold text-[#1C1F2E] mb-3">Sub-entities & Regulated Bodies</h3>
            <div className="flex flex-wrap gap-2">
              {meta.subfields.map(field => (
                <span
                  key={field}
                  className="text-xs px-2.5 py-1 rounded-full border font-medium"
                  style={{ backgroundColor: `${meta.color}10`, borderColor: `${meta.color}30`, color: meta.color }}
                >
                  {field}
                </span>
              ))}
            </div>
          </div>

          {/* Compliance */}
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="font-semibold text-[#1C1F2E] mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#2B3BCC]" /> Applicable Compliance Frameworks
            </h3>
            <div className="flex flex-wrap gap-2">
              {meta.compliance.map(c => (
                <span key={c} className="text-xs bg-[#2B3BCC]/10 text-[#2B3BCC] border border-[#2B3BCC]/20 px-2 py-0.5 rounded-full">{c}</span>
              ))}
            </div>
          </div>

          {/* Nigeria Context */}
          <div className="bg-amber-50 border border-amber-100 rounded-xl p-5">
            <h3 className="font-semibold text-amber-800 mb-2 flex items-center gap-2">
              <TrendingUp className="w-4 h-4" /> Nigeria Threat Context
            </h3>
            <p className="text-sm text-amber-700 leading-relaxed">{meta.nigeriaContext}</p>
          </div>
        </div>
      </div>

      {/* Vulnerabilities */}
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
          <Bug className="w-4 h-4 text-amber-600" /> Vulnerabilities in this Sector
        </h3>
        {!current ? (
          <div className="text-sm text-[#7A8099]">Loading...</div>
        ) : !current.vulns.connected ? (
          <NotConnected what="Vulnerability feed" reason={current.vulns.reason} />
        ) : vulns.length === 0 ? (
          <div className="text-sm text-[#7A8099] py-6 text-center">No vulnerabilities recorded for this sector</div>
        ) : (
          <div className="space-y-2">
            {vulns.map(vuln => (
              <div key={vuln.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 p-3 bg-gray-50 rounded-lg">
                <span className="text-xs font-mono font-bold text-[#2B3BCC]">{vuln.cve}</span>
                <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${SEV_BADGE[vuln.severity]}`}>
                  {vuln.severity.toUpperCase()} · {vuln.cvss}
                </span>
                <span className="text-sm text-[#1C1F2E] flex-1 min-w-0 truncate">{vuln.title}</span>
                <Link href={`/admin/cnii/ip/${encodeURIComponent(vuln.ip)}`} className="text-xs text-[#2B3BCC] hover:underline font-mono">
                  {vuln.ip} →
                </Link>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Assets */}
      <div className="bg-white rounded-xl border border-gray-100 p-5">
        <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
          <Server className="w-4 h-4 text-[#2B3BCC]" /> Monitored Assets
        </h3>
        {!current ? (
          <div className="text-sm text-[#7A8099]">Loading...</div>
        ) : !current.assets.connected ? (
          <NotConnected what="Asset inventory" reason={current.assets.reason} />
        ) : assets.length === 0 ? (
          <div className="text-sm text-[#7A8099] py-6 text-center">No assets in this sector yet</div>
        ) : (
          <div className="space-y-2">
            {assets.map(asset => (
              <Link key={asset.id} href={`/admin/cnii/ip/${encodeURIComponent(asset.ip)}`}
                className="flex flex-wrap items-center gap-x-4 gap-y-1 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors">
                <span className="font-mono text-xs font-bold text-[#2B3BCC]">{asset.ip}</span>
                <span className="text-xs text-[#1C1F2E]">{asset.owner ?? asset.hostname ?? '—'}</span>
                <span className="text-xs text-[#7A8099] flex-1 min-w-0 truncate">{asset.subfield ?? ''}</span>
                <span className="text-xs font-bold" style={{ color: riskColor(asset.riskScore) }}>Risk {asset.riskScore}</span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
