'use client';

import { useParams } from 'next/navigation';
import { useState, useEffect } from 'react';
import { ArrowLeft, Activity, TrendingUp, Zap, Droplets, Wifi, Landmark, HeartPulse, Building, GraduationCap, Swords, Truck, Wheat, AlertTriangle, Factory, Mountain } from 'lucide-react';
import Link from 'next/link';
import type { LucideIcon } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Sector alerts come from GET /api/cnii/sector-alerts/:sector. That endpoint is not built yet, so
// until it answers, the page says the feed is not connected rather than "no active alerts".

interface SectorMeta {
  label: string;
  icon: LucideIcon;
  color: string;
  description: string;
  subfields: string[];
  nigeriaContext: string;
}

const SECTOR_META: Record<string, SectorMeta> = {
  power: {
    label: 'Power & Energy', icon: Zap, color: '#F59E0B',
    description: 'Oil and gas infrastructure, power generation facilities and national electricity distribution network.',
    subfields: ['Oil & Gas', 'Power Generation & Distribution'],
    nigeriaContext: 'Nigeria generates ~4,000 MW against 30,000+ MW demand. NNPC pipeline SCADA and GenCo control systems are high-value targets. OT/ICS attacks on power infrastructure carry immediate national economic impact.',
  },
  water: {
    label: 'Water', icon: Droplets, color: '#06B6D4',
    description: 'National water treatment, dam control systems and water distribution infrastructure.',
    subfields: ['Dams & Water Stations'],
    nigeriaContext: 'Kainji, Jebba and Shiroro dams serve both power generation and water supply. SCADA attacks on dam systems carry cascading national risk across electricity and public water supply.',
  },
  ict: {
    label: 'ICT & Communications', icon: Wifi, color: '#2B3BCC',
    description: 'Telecommunications, internet infrastructure, national identity systems and satellite communications.',
    subfields: ['Communications Companies', 'ISPs / Exchange Points (NiRA)', 'Nigerian Communications Commission (NCC)', 'Galaxy Backbone', 'National Identity Management Commission (NIMC)', 'Nigerian Communications Satellite (NigCOMSAT)'],
    nigeriaContext: 'Nigeria has 220M+ SIM subscribers. Galaxy Backbone carries Federal Government network traffic. NIMC holds biometric records for 100M+ Nigerians — a primary APT target. NiRA manages the .ng domain namespace.',
  },
  finance: {
    label: 'Banking, Finance & Insurance', icon: Landmark, color: '#10B981',
    description: 'Interbank payment systems, CBN infrastructure, federal payroll systems and financial trading platforms.',
    subfields: ['Inter-Bank Payment Systems', 'Electronic Transactions / CBN', 'Federal Civil Service Payroll (IPPIS)', 'Financial Trading', 'National Health Insurance Scheme (NHIS)'],
    nigeriaContext: 'NIBSS processes $500B+ annually. CBN Cybersecurity Framework (2022) mandates SOC operations for all DMBs. IPPIS handles payroll for 1M+ federal civil servants — a high-value ransomware target.',
  },
  health: {
    label: 'Health', icon: HeartPulse, color: '#EC4899',
    description: 'Hospitals, disease surveillance, drug regulation and national primary healthcare systems.',
    subfields: ['Hospitals', 'Nigeria Centre for Disease Control (NCDC)', 'National Agency for Food & Drug Administration (NAFDAC)', 'National Institute for Medical Research (NIMR)', 'National Primary Health Care Development Agency (NPHCDA)'],
    nigeriaContext: 'Post-COVID NCDC digital surveillance is critical to outbreak response. Ransomware targeting teaching hospitals and NAFDAC drug supply chains is an active documented threat across Africa.',
  },
  publicadmin: {
    label: 'Public Administration', icon: Building, color: '#8B5CF6',
    description: 'Federal ministries, immigration, revenue, correctional services and electoral infrastructure.',
    subfields: ['Ministries, Departments & Agencies (MDAs)', 'Nigeria Immigration Service (NIS)', 'Federal Inland Revenue Service (FIRS)', 'Nigerian Correctional Service (NCoS)', 'Independent National Electoral Commission (INEC)'],
    nigeriaContext: 'INEC electoral systems are a persistent target during election cycles. FIRS digital tax infrastructure processes national revenue. NIS passport and border systems are high-sensitivity citizen data stores.',
  },
  education: {
    label: 'Education', icon: GraduationCap, color: '#84CC16',
    description: 'National examination bodies, tertiary education funding and basic education systems.',
    subfields: ['Joint Admissions & Matriculation Board (JAMB)', 'West African Examinations Council (WAEC)', 'National Examinations Council (NECO)', 'Tertiary Education Trust Fund (TETFund)', 'Universal Basic Education Commission (UBEC)'],
    nigeriaContext: 'JAMB and WAEC portals hold records for millions of candidates annually. Exam portal breaches, result manipulation and credential fraud are documented attack patterns targeting Nigeria\'s education sector.',
  },
  defence: {
    label: 'Defence & Security', icon: Swords, color: '#CC2B2B',
    description: 'Armed forces, intelligence agencies, law enforcement, financial crime units and border security.',
    subfields: ['Nigerian Army', 'Nigerian Navy', 'Nigerian Air Force (NAF)', 'Defence Space Administration (DSA)', 'Office of the National Security Adviser (ONSA)', 'Defence Intelligence Agency (DIA)', 'Department of State Services (DSS)', 'National Intelligence Agency (NIA)', 'NCCSALW', 'Nigeria Police Force (NPF)', 'NSCDC', 'Nigeria Customs Service (NCS)', 'NDLEA', 'EFCC', 'Nigerian Financial Intelligence Unit (NFIU)', 'DICON / NDA / NDC / Naval Dockyard'],
    nigeriaContext: 'DSA and NAF satellite infrastructure are strategic state targets. DSS and NIA systems hold classified intelligence. EFCC and NFIU financial intelligence databases are targeted by organised cybercrime groups disrupting anti-corruption efforts.',
  },
  transport: {
    label: 'Transport', icon: Truck, color: '#6366F1',
    description: 'Aviation authority, airspace management, railways, ports and maritime safety infrastructure.',
    subfields: ['Federal Airports Authority of Nigeria (FAAN)', 'Nigerian Civil Aviation Authority (NCAA)', 'Nigerian Airspace Management Agency (NAMA)', 'Nigerian College of Aviation Technology (NCAT)', 'Nigerian Meteorological Agency (NiMet)', 'Accident Investigation Bureau (AIB)', 'Nigerian Railway Corporation (NRC)', 'Nigerian Ports Authority (NPA)', 'Nigerian Maritime Administration & Safety Agency (NIMASA)'],
    nigeriaContext: 'Murtala Muhammed and other international airports handle millions of passengers. NAMA ATC systems and NPA port management are critical chokepoints where cyber disruption carries direct physical-safety consequences.',
  },
  food: {
    label: 'Food & Agriculture', icon: Wheat, color: '#65A30D',
    description: 'Agricultural lending risk systems and national food security infrastructure.',
    subfields: ['Nigeria Incentive-Based Risk Sharing System for Agricultural Lending (NIRSAL)'],
    nigeriaContext: 'Agriculture employs 36% of Nigerians. NIRSAL digital platforms underpin billions in agricultural credit. Data integrity attacks on lending systems directly impact smallholder farmer access to finance.',
  },
  safety: {
    label: 'Safety & Emergency Services', icon: AlertTriangle, color: '#F97316',
    description: 'National disaster management and road safety command infrastructure.',
    subfields: ['National Emergency Management Agency (NEMA)', 'Federal Road Safety Corps (FRSC)'],
    nigeriaContext: 'NEMA coordinates emergency response during floods, oil spills and security incidents. FRSC systems manage road safety enforcement nationally. Communication disruption during emergencies is a direct life-safety risk.',
  },
  industrial: {
    label: 'Industrial & Manufacturing', icon: Factory, color: '#78716C',
    description: 'Critical industrial production sectors including textiles, automotive and strategic manufacturing.',
    subfields: ['Textile Industry', 'Automobile Sector', 'Other Critical Industrial Sectors'],
    nigeriaContext: 'Industrial OT/ICS environments are increasingly networked. Supply chain attacks targeting Nigerian manufacturing are an emerging risk as the sector digitises under the Nigeria Industrial Revolution Plan (NIRP).',
  },
  mines: {
    label: 'Mines & Steel', icon: Mountain, color: '#92400E',
    description: 'Solid mineral extraction, steel production and major mining infrastructure.',
    subfields: ['Solid Minerals Sector', 'Ajaokuta Steel Company', 'Major Mines & Steel Entities'],
    nigeriaContext: 'Ajaokuta Steel is a strategic national asset. The Mining Cadastre Office digital platform manages mineral titles. As Nigeria diversifies from oil, solid minerals ICT infrastructure becomes an increasingly attractive target.',
  },
};

interface Alert {
  id: string;
  rule_description: string;
  severity: number;
  agent_name: string;
  timestamp: string;
}

// Result for one sector; the page is "loading" whenever the result is for a different sector.
interface Loaded { sector: string; alerts: Alert[] | null } // alerts null = feed unavailable

export default function SectorPage() {
  const params = useParams();
  const sector = params.sector as string;
  const meta = SECTOR_META[sector];
  const [loaded, setLoaded] = useState<Loaded | null>(null);

  useEffect(() => {
    if (!SECTOR_META[sector]) return;
    let active = true;
    apiFetch(apiUrl(`/api/cnii/sector-alerts/${encodeURIComponent(sector)}`), { cache: 'no-store' })
      .then(async r => {
        const d = r.ok ? await r.json().catch(() => null) : null;
        if (active) setLoaded({ sector, alerts: Array.isArray(d?.alerts) ? d.alerts as Alert[] : null });
      })
      .catch(() => { if (active) setLoaded({ sector, alerts: null }); });
    return () => { active = false; };
  }, [sector]);

  if (!meta) return (
    <div className="p-6">
      <p className="text-[#7A8099] mb-2">Sector not found.</p>
      <Link href="/admin/cnii" className="text-[#2B3BCC] text-sm">← Back to CNII Watch</Link>
    </div>
  );

  const loading = loaded?.sector !== sector;
  const alerts = !loading ? loaded?.alerts ?? null : null;
  const connected = alerts !== null;
  const Icon = meta.icon;
  const criticalCount = alerts?.filter(a => a.severity >= 12).length ?? 0;
  const highCount = alerts?.filter(a => a.severity >= 7 && a.severity < 12).length ?? 0;
  const show = (n: number) => (connected ? n : '—');

  return (
    <div className="p-6 space-y-6">
      {/* Back + Header */}
      <div>
        <Link href="/admin/cnii" className="text-sm text-[#7A8099] hover:text-[#2B3BCC] flex items-center gap-1 mb-3 w-fit">
          <ArrowLeft className="w-3 h-3" /> CNII Watch
        </Link>
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl flex items-center justify-center" style={{ backgroundColor: `${meta.color}18` }}>
            <Icon className="w-6 h-6" style={{ color: meta.color }} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[#1C1F2E]">{meta.label}</h1>
            <p className="text-[#7A8099] text-sm">{meta.description}</p>
          </div>
        </div>
      </div>

      {/* Alert Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-100 p-4">
          <div className="text-2xl font-bold text-[#CC2B2B]">{show(criticalCount)}</div>
          <div className="text-sm text-[#7A8099]">Critical Alerts</div>
        </div>
        <div className="bg-white rounded-xl border border-gray-100 p-4">
          <div className="text-2xl font-bold text-amber-600">{show(highCount)}</div>
          <div className="text-sm text-[#7A8099]">High Alerts</div>
        </div>
        <div className="bg-white rounded-xl border border-gray-100 p-4">
          <div className="text-2xl font-bold text-[#1C1F2E]">{show(alerts?.length ?? 0)}</div>
          <div className="text-sm text-[#7A8099]">Total Active</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Live Alerts */}
        <div className="bg-white rounded-xl border border-gray-100 p-5">
          <h3 className="font-semibold text-[#1C1F2E] mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#2B3BCC]" /> Live Alerts
          </h3>
          {loading ? (
            <div className="text-sm text-[#7A8099]">Loading...</div>
          ) : !connected ? (
            <div className="text-sm text-[#7A8099] py-8 text-center">
              Sector alert feed not connected — alerts can&apos;t be matched to this sector yet.
            </div>
          ) : alerts.length === 0 ? (
            <div className="text-sm text-[#7A8099] py-8 text-center">No active alerts for this sector</div>
          ) : (
            <div className="space-y-3">
              {alerts.slice(0, 8).map(alert => (
                <div key={alert.id} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                  <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                    alert.severity >= 12 ? 'bg-red-500' : alert.severity >= 7 ? 'bg-amber-500' : 'bg-blue-400'
                  }`} />
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
          {/* Sub-entity Cards */}
          <div className="bg-white rounded-xl border border-gray-100 p-5">
            <h3 className="font-semibold text-[#1C1F2E] mb-3">Sub-entities & Regulated Bodies</h3>
            <div className="flex flex-wrap gap-2">
              {meta.subfields.map(field => (
                <span
                  key={field}
                  className="text-xs px-2.5 py-1 rounded-full border font-medium"
                  style={{
                    backgroundColor: `${meta.color}10`,
                    borderColor: `${meta.color}30`,
                    color: meta.color,
                  }}
                >
                  {field}
                </span>
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
    </div>
  );
}
