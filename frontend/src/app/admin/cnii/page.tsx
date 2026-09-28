'use client';

import { useState, useEffect } from 'react';
import { Shield, Activity, TrendingUp, Zap, Radio, Landmark, Database, Router, Monitor, Globe, Building2 } from 'lucide-react';
import Link from 'next/link';

const SECTORS = [
  { id: 'power', label: 'Power & Energy', icon: Zap, color: '#F59E0B', status: 'stable' },
  { id: 'telecoms', label: 'Telecoms & ICT', icon: Radio, color: '#2B3BCC', status: 'stable' },
  { id: 'finance', label: 'Financial Services', icon: Landmark, color: '#10B981', status: 'elevated' },
  { id: 'oilandgas', label: 'Oil & Gas', icon: Activity, color: '#EF4444', status: 'stable' },
  { id: 'water', label: 'Water & Sanitation', icon: Database, color: '#06B6D4', status: 'stable' },
  { id: 'transport', label: 'Transportation', icon: Router, color: '#8B5CF6', status: 'stable' },
  { id: 'health', label: 'Health', icon: Monitor, color: '#EC4899', status: 'stable' },
  { id: 'food', label: 'Food & Agriculture', icon: Globe, color: '#84CC16', status: 'stable' },
  { id: 'government', label: 'Government & Defence', icon: Building2, color: '#CC2B2B', status: 'elevated' },
];

const STATUS_CONFIG = {
  stable:   { label: 'Stable',   bg: 'bg-green-50',  text: 'text-green-700',  dot: 'bg-green-500' },
  elevated: { label: 'Elevated', bg: 'bg-amber-50',  text: 'text-amber-700',  dot: 'bg-amber-500' },
  critical: { label: 'Critical', bg: 'bg-red-50',    text: 'text-red-700',    dot: 'bg-red-500' },
};

export default function CNIIWatchPage() {
  const [alerts, setAlerts] = useState<Record<string, number>>({});

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await fetch('/api/cnii/sector-alerts');
        if (res.ok) {
          const data = await res.json();
          setAlerts(data);
        }
      } catch {
        // silent
      }
    };
    fetchAlerts();
  }, []);

  const elevated = SECTORS.filter(s => s.status !== 'stable').length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#1C1F2E] flex items-center gap-2">
            <Shield className="w-6 h-6 text-[#2B3BCC]" />
            CNII Watch
          </h1>
          <p className="text-[#7A8099] text-sm mt-1">
            Nigeria Critical National Information Infrastructure — real-time threat monitoring across 9 sectors
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-[#7A8099]">
          <span className="w-2 h-2 rounded-full bg-green-500 inline-block animate-pulse" />
          Live monitoring active
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-100 p-4">
          <div className="text-2xl font-bold text-[#1C1F2E]">9</div>
          <div className="text-sm text-[#7A8099]">Sectors Monitored</div>
        </div>
        <div className="bg-white rounded-xl border border-gray-100 p-4">
          <div className="text-2xl font-bold text-amber-600">{elevated}</div>
          <div className="text-sm text-[#7A8099]">Elevated Risk</div>
        </div>
        <div className="bg-white rounded-xl border border-gray-100 p-4">
          <div className="text-2xl font-bold text-[#CC2B2B]">
            {(Object.values(alerts) as number[]).reduce((a, b) => a + b, 0)}
          </div>
          <div className="text-sm text-[#7A8099]">Active Alerts</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {SECTORS.map(sector => {
          const Icon = sector.icon;
          const status = STATUS_CONFIG[sector.status as keyof typeof STATUS_CONFIG];
          const count = alerts[sector.id] || 0;
          return (
            <Link
              key={sector.id}
              href={`/admin/cnii/${sector.id}`}
              className="bg-white rounded-xl border border-gray-100 p-5 hover:shadow-md hover:border-[#2B3BCC]/20 transition-all group"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${sector.color}15` }}>
                  <Icon className="w-5 h-5" style={{ color: sector.color }} />
                </div>
                <div className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${status.bg} ${status.text}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${status.dot}`} />
                  {status.label}
                </div>
              </div>
              <div className="font-semibold text-[#1C1F2E] group-hover:text-[#2B3BCC] transition-colors">{sector.label}</div>
              <div className="mt-3 flex items-center justify-between text-sm">
                <span className="text-[#7A8099]">Active alerts</span>
                <span className={`font-bold ${count > 0 ? 'text-[#CC2B2B]' : 'text-[#7A8099]'}`}>{count}</span>
              </div>
              <div className="mt-3 w-full bg-gray-100 rounded-full h-1">
                <div className="h-1 rounded-full transition-all" style={{ width: `${Math.min((count / 10) * 100, 100)}%`, backgroundColor: count > 5 ? '#CC2B2B' : count > 0 ? '#F59E0B' : '#10B981' }} />
              </div>
            </Link>
          );
        })}
      </div>

      <div className="bg-[#2B3BCC]/5 border border-[#2B3BCC]/10 rounded-xl p-5">
        <h3 className="font-semibold text-[#1C1F2E] mb-2">About Nigeria CNII</h3>
        <p className="text-sm text-[#7A8099] leading-relaxed">
          Nigeria&apos;s Critical National Information Infrastructure (CNII) is defined under the Cybercrimes
          (Prohibition, Prevention, etc.) Act 2015 as systems and assets vital to national security,
          governance, economic stability and public safety. NovrSOC monitors cyber threats targeting
          all 9 designated sectors in real time, correlating Wazuh alerts with threat intelligence
          from ThreatFox, OpenCTI, and Nigeria-specific advisory feeds.
        </p>
      </div>
    </div>
  );
}
