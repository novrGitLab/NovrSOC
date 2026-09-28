'use client';

import { useParams } from 'next/navigation';
import { useState, useEffect } from 'react';
import { Shield, ArrowLeft, Activity, TrendingUp } from 'lucide-react';
import Link from 'next/link';

const SECTOR_META: Record<string, { label: string; description: string; keyAssets: string[]; regulators: string[]; color: string; nigeriaContext: string; }> = {
  power: { label: 'Power & Energy', description: 'Electricity generation, transmission and distribution infrastructure including NERC-regulated utilities.', keyAssets: ['NERC control systems', 'GenCo SCADA', 'TCN transmission grid', 'DisCo distribution networks'], regulators: ['NERC', 'TCN', 'REA'], color: '#F59E0B', nigeriaContext: 'Nigeria generates ~4,000 MW against 30,000+ MW demand. Grid instability makes SCADA systems high-value targets.' },
  telecoms: { label: 'Telecoms & ICT', description: 'Telecommunications networks, internet infrastructure, data centres and ICT service providers.', keyAssets: ['MTN/Airtel/Glo core networks', 'NCC-licensed ISPs', 'IXP Nigeria', 'Submarine cable landing stations'], regulators: ['NCC', 'NigCERT', 'NITDA'], color: '#2B3BCC', nigeriaContext: 'Nigeria has 220M+ SIM subscribers. NCC mandates cybersecurity frameworks for all licensed operators.' },
  finance: { label: 'Financial Services', description: 'Banking, payment systems, capital markets and insurance infrastructure.', keyAssets: ['CBN RTGS', 'NIBSS interbank settlement', 'Licensed DMBs', 'Fintech payment processors'], regulators: ['CBN', 'SEC', 'NAICOM', 'EFCC'], color: '#10B981', nigeriaContext: 'CBN Cybersecurity Framework (2022) mandates SOC operations for all banks. Nigeria processes $500B+ annually through NIBSS.' },
  oilandgas: { label: 'Oil & Gas', description: 'Upstream exploration, midstream pipelines and downstream refining and distribution.', keyAssets: ['NNPC pipeline SCADA', 'NLNG facilities', 'Offshore production platforms', 'Atlas Cove depot'], regulators: ['NUPRC', 'NMDPRA', 'DPR'], color: '#EF4444', nigeriaContext: "Oil & gas accounts for 90% of Nigeria's forex earnings. Pipeline SCADA attacks directly impact national revenue." },
  water: { label: 'Water & Sanitation', description: 'Water treatment facilities, distribution networks and sanitation infrastructure.', keyAssets: ['State water boards', 'Treatment plant SCADA', 'Dams (Kainji, Jebba, Shiroro)', 'Urban water utilities'], regulators: ['FMWR', 'State water agencies'], color: '#06B6D4', nigeriaContext: 'Only 19% of Nigerians have piped water access. OT attacks on water treatment pose direct public health risk.' },
  transport: { label: 'Transportation', description: 'Aviation, rail, road and maritime transportation systems and logistics networks.', keyAssets: ['NCAA ATC systems', 'NRC rail control', 'NPA port management', 'NIMASA vessel tracking'], regulators: ['NCAA', 'NRC', 'NPA', 'NIMASA'], color: '#8B5CF6', nigeriaContext: 'Murtala Muhammed Airport handles 10M+ passengers annually. ATC and port logistics systems are primary targets.' },
  health: { label: 'Health', description: 'Hospitals, health information systems, pharmaceutical supply chains and public health infrastructure.', keyAssets: ['NHIA health records', 'Teaching hospital networks', 'NAFDAC supply chain', 'NCDC surveillance systems'], regulators: ['FMOH', 'NHIA', 'NAFDAC', 'NCDC'], color: '#EC4899', nigeriaContext: 'Post-COVID, Nigeria is digitising health records nationally. Ransomware targeting hospital systems is rising across Africa.' },
  food: { label: 'Food & Agriculture', description: 'Agricultural production systems, food processing, storage and distribution infrastructure.', keyAssets: ['AFEX commodity exchange', 'Grain reserve management', 'Anchor borrowers programme systems', 'FMARD databases'], regulators: ['FMARD', 'NASC', 'SON'], color: '#84CC16', nigeriaContext: 'Agriculture employs 36% of Nigerians. Digital farming platforms and commodity systems are emerging attack surfaces.' },
  government: { label: 'Government & Defence', description: 'Federal and state government systems, defence infrastructure, law enforcement and intelligence.', keyAssets: ['NIN/NIMC identity systems', 'IPPIS payroll', 'DSS/NIA systems', 'INEC electoral systems'], regulators: ['OHCSF', 'NSA', 'DSS', 'NCC'], color: '#CC2B2B', nigeriaContext: 'INEC and NIN are high-profile targets. Election infrastructure and national identity databases face persistent APT activity.' },
};

interface Alert { id: string; rule_description: string; severity: number; agent_name: string; timestamp: string; status: string; }

export default function SectorPage() {
  const params = useParams();
  const sector = params.sector as string;
  const meta = SECTOR_META[sector];
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSectorAlerts = async () => {
      try {
        const res = await fetch(`/api/cnii/sector-alerts/${sector}`);
        if (res.ok) { const data = await res.json(); setAlerts(data.alerts || []); }
      } catch { /* silent */ } finally { setLoading(false); }
    };
    fetchSectorAlerts();
  }, [sector]);

  if (!meta) return (
    <div className="p-6">
      <p className="text-[#7A8099]">Sector not found.</p>
      <Link href="/admin/cnii" className="text-[#2B3BCC] text-sm mt-2 inline-block">← Back to CNII Watch</Link>
    </div>
  );

  const criticalCount = alerts.filter(a => a.severity >= 12).length;
  const highCount = alerts.filter(a => a.severity >= 7 && a.severity < 12).length;

  return (
    <div className="p-6 space-y-6">
      <div>
        <Link href="/admin/cnii" className="text-sm text-[#7A8099] hover:text-[#2B3BCC] flex items-center gap-1 mb-3">
          <ArrowLeft className="w-3 h-3" /> CNII Watch
        </Link>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${meta.color}15` }}>
            <Shield className="w-5 h-5" style={{ color: meta.color }} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[#1C1F2E]">{meta.label}</h1>
            <p className="text-[#7A8099] text-sm">{meta.description}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-100 p-4"><div className="text-2xl font-bold text-[#CC2B2B]">{criticalCount}</div><div className="text-sm text-[#7A8099]">Critical Alerts</div></div>
        <div className="bg-white rounded-xl border border-gray-100 p-4"><div className="text-2xl font-bold text-amber-600">{highCount}</div><div className="text-sm text-[#7A8099]">High Alerts</div></div>
        <div className="bg-white rounded-xl border border-gray-100 p-4"><div className="text-2xl font-bold text-[#1C1F2E]">{alerts.length}</div><div className="text-sm text-[#7A8099]">Total Active</div></div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-gray-100 p-5">
          <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2"><Activity className="w-4 h-4 text-[#2B3BCC]" /> Live Alerts</h3>
          {loading ? <div className="text-sm text-[#7A8099]">Loading...</div> : alerts.length === 0 ? (
            <div className="text-sm text-[#7A8099] py-8 text-center">No active alerts for this sector</div>
          ) : (
            <div className="space-y-3">
              {alerts.slice(0, 8).map(alert => (
                <div key={alert.id} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                  <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${alert.severity >= 12 ? 'bg-red-500' : alert.severity >= 7 ? 'bg-amber-500' : 'bg-blue-500'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-[#1C1F2E] truncate">{alert.rule_description}</div>
                    <div className="text-xs text-[#7A8099]">{alert.agent_name} · {new Date(alert.timestamp).toLocaleTimeString()}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="font-semibold text-[#1C1F2E] mb-3">Key Assets at Risk</h3>
            <ul className="space-y-2">
              {meta.keyAssets.map(asset => (
                <li key={asset} className="text-sm text-[#7A8099] flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#2B3BCC] flex-shrink-0" />{asset}
                </li>
              ))}
            </ul>
          </div>
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="font-semibold text-[#1C1F2E] mb-3">Regulators & Bodies</h3>
            <div className="flex flex-wrap gap-2">
              {meta.regulators.map(reg => (
                <span key={reg} className="text-xs bg-[#2B3BCC]/10 text-[#2B3BCC] px-2 py-1 rounded-full font-medium">{reg}</span>
              ))}
            </div>
          </div>
          <div className="bg-amber-50 border border-amber-100 rounded-xl p-5">
            <h3 className="font-semibold text-amber-800 mb-2 flex items-center gap-2"><TrendingUp className="w-4 h-4" /> Nigeria Context</h3>
            <p className="text-sm text-amber-700 leading-relaxed">{meta.nigeriaContext}</p>
          </div>
        </div>
      </div>
    </div>
  );
}