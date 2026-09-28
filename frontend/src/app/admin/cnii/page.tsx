'use client';

import { useState, useEffect } from 'react';
import { Shield, Zap, Droplets, Wifi, Landmark, HeartPulse, Building, GraduationCap, Swords, Truck, Wheat, AlertTriangle, Factory, Mountain } from 'lucide-react';
import Link from 'next/link';
import { apiUrl, apiFetch } from '@/lib/api';

// Sector alert counts come from GET /api/cnii/sector-alerts. That endpoint is not built yet, so
// until it answers, the page says the feed is not connected rather than showing zero alerts.

const SECTORS = [
  {
    id: 'power', label: 'Power & Energy', icon: Zap, color: '#F59E0B',
    subfields: ['Oil & Gas', 'Power Generation & Distribution'],
  },
  {
    id: 'water', label: 'Water', icon: Droplets, color: '#06B6D4',
    subfields: ['Dams & Water Stations'],
  },
  {
    id: 'ict', label: 'ICT & Communications', icon: Wifi, color: '#2B3BCC',
    subfields: ['Communications Companies', 'ISPs / Exchange Points (NiRA)', 'NCC', 'Galaxy Backbone', 'NIMC', 'NigCOMSAT'],
  },
  {
    id: 'finance', label: 'Banking, Finance & Insurance', icon: Landmark, color: '#10B981',
    subfields: ['Inter-Bank Payment Systems', 'Electronic Transactions / CBN', 'Federal Civil Service Payroll (IPPIS)', 'Financial Trading', 'National Health Insurance Scheme (NHIS)'],
  },
  {
    id: 'health', label: 'Health', icon: HeartPulse, color: '#EC4899',
    subfields: ['Hospitals', 'NCDC', 'NAFDAC', 'NIMR', 'NPHCDA'],
  },
  {
    id: 'publicadmin', label: 'Public Administration', icon: Building, color: '#8B5CF6',
    subfields: ['Ministries, Departments & Agencies (MDAs)', 'Nigeria Immigration Service (NIS)', 'FIRS', 'Nigerian Correctional Service (NCoS)', 'INEC'],
  },
  {
    id: 'education', label: 'Education', icon: GraduationCap, color: '#84CC16',
    subfields: ['JAMB', 'WAEC', 'NECO', 'TETFund', 'UBEC'],
  },
  {
    id: 'defence', label: 'Defence & Security', icon: Swords, color: '#CC2B2B',
    subfields: ['Nigerian Army', 'Nigerian Navy', 'Nigerian Air Force (NAF)', 'DSA', 'ONSA', 'DIA', 'DSS', 'NIA', 'NPF', 'NSCDC', 'NCS', 'NDLEA', 'EFCC', 'NFIU', 'DICON / NDA / NDC'],
  },
  {
    id: 'transport', label: 'Transport', icon: Truck, color: '#6366F1',
    subfields: ['FAAN', 'NCAA', 'NAMA', 'NCAT', 'NiMet', 'AIB', 'NRC', 'NPA', 'NIMASA'],
  },
  {
    id: 'food', label: 'Food & Agriculture', icon: Wheat, color: '#65A30D',
    subfields: ['NIRSAL'],
  },
  {
    id: 'safety', label: 'Safety & Emergency Services', icon: AlertTriangle, color: '#F97316',
    subfields: ['NEMA', 'FRSC'],
  },
  {
    id: 'industrial', label: 'Industrial & Manufacturing', icon: Factory, color: '#78716C',
    subfields: ['Textiles', 'Automobiles', 'Other Critical Industrial Sectors'],
  },
  {
    id: 'mines', label: 'Mines & Steel', icon: Mountain, color: '#92400E',
    subfields: ['Solid Minerals', 'Ajaokuta Steel Company', 'Major Mines & Steel Entities'],
  },
];

export default function CNIIWatchPage() {
  // null while loading; 'unavailable' when the endpoint doesn't answer.
  const [alerts, setAlerts] = useState<Record<string, number> | 'unavailable' | null>(null);

  useEffect(() => {
    apiFetch(apiUrl('/api/cnii/sector-alerts'), { cache: 'no-store' })
      .then(async r => {
        const d = r.ok ? await r.json().catch(() => null) : null;
        setAlerts(d && typeof d === 'object' ? d as Record<string, number> : 'unavailable');
      })
      .catch(() => setAlerts('unavailable'));
  }, []);

  const connected = alerts !== null && alerts !== 'unavailable';
  const counts = connected ? alerts : {};
  const totalAlerts = (Object.values(counts) as number[]).reduce((a, b) => a + b, 0);
  const totalSubfields = SECTORS.reduce((a, s) => a + s.subfields.length, 0);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#1C1F2E] flex items-center gap-2">
            <Shield className="w-6 h-6 text-[#2B3BCC]" />
            CNII Watch
          </h1>
          <p className="text-[#7A8099] text-sm mt-1">
            Nigeria Critical National Information Infrastructure — 13 designated sectors under the Cybercrimes Act 2015
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-[#7A8099]">
          <span className={`w-2 h-2 rounded-full inline-block ${connected ? 'bg-green-500 animate-pulse' : 'bg-gray-300'}`} />
          {alerts === null ? 'Checking alert feed…' : connected ? 'Sector alert feed connected' : 'Sector alert feed not connected'}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Sectors Designated', value: SECTORS.length, color: 'text-[#1C1F2E]' },
          { label: 'Sub-entities Listed', value: totalSubfields, color: 'text-[#2B3BCC]' },
          { label: 'Active Alerts', value: connected ? totalAlerts : '—', color: connected && totalAlerts > 0 ? 'text-[#CC2B2B]' : 'text-[#1C1F2E]' },
        ].map(stat => (
          <div key={stat.label} className="bg-white rounded-xl border border-gray-100 p-4">
            <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-sm text-[#7A8099]">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Sector Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {SECTORS.map(sector => {
          const Icon = sector.icon;
          const count = counts[sector.id] || 0;
          return (
            <Link
              key={sector.id}
              href={`/admin/cnii/${sector.id}`}
              className="bg-white rounded-xl border border-gray-100 p-5 hover:shadow-md hover:border-[#2B3BCC]/20 transition-all group block"
            >
              {/* Sector header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: `${sector.color}18` }}>
                    <Icon className="w-5 h-5" style={{ color: sector.color }} />
                  </div>
                  <div className="font-semibold text-[#1C1F2E] group-hover:text-[#2B3BCC] transition-colors leading-tight">
                    {sector.label}
                  </div>
                </div>
                {count > 0 && (
                  <span className="text-xs font-bold text-[#CC2B2B] bg-red-50 px-2 py-0.5 rounded-full flex-shrink-0">
                    {count} alert{count !== 1 ? 's' : ''}
                  </span>
                )}
              </div>

              {/* Sub-entity chips */}
              <div className="flex flex-wrap gap-1.5 mb-4">
                {sector.subfields.map(sf => (
                  <span
                    key={sf}
                    className="text-xs px-2 py-0.5 rounded-full border"
                    style={{
                      backgroundColor: `${sector.color}10`,
                      borderColor: `${sector.color}30`,
                      color: sector.color,
                    }}
                  >
                    {sf}
                  </span>
                ))}
              </div>

              {/* Alert bar — only when there is real data behind it */}
              <div className="flex items-center gap-2">
                {connected ? (
                  <div className="flex-1 bg-gray-100 rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full transition-all"
                      style={{
                        width: `${Math.min((count / 10) * 100, 100)}%`,
                        backgroundColor: count > 5 ? '#CC2B2B' : count > 0 ? '#F59E0B' : '#10B981',
                      }}
                    />
                  </div>
                ) : (
                  <span className="flex-1 text-xs text-[#7A8099]">Alerts not connected</span>
                )}
                <span className="text-xs text-[#7A8099] whitespace-nowrap">
                  {sector.subfields.length} entities
                </span>
              </div>
            </Link>
          );
        })}
      </div>

      {/* Footer note */}
      <div className="bg-[#2B3BCC]/5 border border-[#2B3BCC]/10 rounded-xl p-4 text-sm text-[#7A8099] leading-relaxed">
        <span className="font-medium text-[#1C1F2E]">Legal basis: </span>
        Nigeria CNII sectors are designated under the Cybercrimes (Prohibition, Prevention, etc.) Act 2015 and
        the National Cybersecurity Policy & Strategy (NCPS) 2021.
        {!connected && alerts !== null && (
          <> Sector-level alert correlation (Wazuh alerts matched to sectors) is not connected yet, so no alert counts are shown.</>
        )}
      </div>
    </div>
  );
}
