// The 13 Nigeria CNII sectors — the single source of truth for CNII Watch pages.
// (AdminSidebar.tsx keeps its own shorter nav labels; the sector ids there must match these.)
import { Zap, Droplets, Wifi, Landmark, HeartPulse, Building, GraduationCap, Swords, Truck, Wheat, AlertTriangle, Factory, Mountain } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export interface CniiSector {
  id: string;
  label: string;
  color: string;
  icon: LucideIcon;
  subfields: string[];
  compliance: string[];
  description: string;
  nigeriaContext: string;
}

export const CNII_SECTORS: CniiSector[] = [
  { id: 'power',       label: 'Power & Energy',              color: '#F59E0B', icon: Zap, compliance: ['NDPR', 'NERC CIP'],
    subfields: ['Oil & Gas', 'Power Generation & Distribution'],
    description: 'Oil and gas infrastructure, power generation facilities and national electricity distribution network.',
    nigeriaContext: 'Nigeria generates ~4,000 MW against 30,000+ MW demand. NNPC pipeline SCADA and GenCo control systems are high-value targets. OT/ICS attacks on power infrastructure carry immediate national economic impact.' },
  { id: 'water',       label: 'Water',                       color: '#06B6D4', icon: Droplets, compliance: ['NDPR'],
    subfields: ['Dams & Water Stations'],
    description: 'National water treatment, dam control systems and water distribution infrastructure.',
    nigeriaContext: 'Kainji, Jebba and Shiroro dams serve both power generation and water supply. SCADA attacks on dam systems carry cascading national risk across electricity and public water supply.' },
  { id: 'ict',         label: 'ICT & Communications',        color: '#2B3BCC', icon: Wifi, compliance: ['NDPR', 'NCC Framework', 'ISO 27001'],
    subfields: ['Communications Companies', 'ISPs / Exchange Points (NiRA)', 'NCC', 'Galaxy Backbone', 'NIMC', 'NigCOMSAT'],
    description: 'Telecommunications, internet infrastructure, national identity systems and satellite communications.',
    nigeriaContext: 'Nigeria has 220M+ SIM subscribers. Galaxy Backbone carries Federal Government network traffic. NIMC holds biometric records for 100M+ Nigerians — a primary APT target. NiRA manages the .ng domain namespace.' },
  { id: 'finance',     label: 'Banking, Finance & Insurance', color: '#10B981', icon: Landmark, compliance: ['NDPR', 'CBN Cybersecurity Framework', 'PCI-DSS', 'ISO 27001'],
    subfields: ['Inter-Bank Payment Systems', 'Electronic Transactions / CBN', 'Federal Civil Service Payroll (IPPIS)', 'Financial Trading', 'NHIS'],
    description: 'Interbank payment systems, CBN infrastructure, federal payroll systems and financial trading platforms.',
    nigeriaContext: 'NIBSS processes $500B+ annually. CBN Cybersecurity Framework (2022) mandates SOC operations for all DMBs. IPPIS handles payroll for 1M+ federal civil servants — a high-value ransomware target.' },
  { id: 'health',      label: 'Health',                      color: '#EC4899', icon: HeartPulse, compliance: ['NDPR', 'ISO 27001'],
    subfields: ['Hospitals', 'NCDC', 'NAFDAC', 'NIMR', 'NPHCDA'],
    description: 'Hospitals, disease surveillance, drug regulation and national primary healthcare systems.',
    nigeriaContext: 'Post-COVID NCDC digital surveillance is critical to outbreak response. Ransomware targeting teaching hospitals and NAFDAC drug supply chains is an active documented threat across Africa.' },
  { id: 'publicadmin', label: 'Public Administration',       color: '#8B5CF6', icon: Building, compliance: ['NDPR', 'ISO 27001'],
    subfields: ['MDAs', 'Nigeria Immigration Service', 'FIRS', 'Nigerian Correctional Service', 'INEC'],
    description: 'Federal ministries, immigration, revenue, correctional services and electoral infrastructure.',
    nigeriaContext: 'INEC electoral systems are a persistent target during election cycles. FIRS digital tax infrastructure processes national revenue. NIS passport and border systems are high-sensitivity citizen data stores.' },
  { id: 'education',   label: 'Education',                   color: '#84CC16', icon: GraduationCap, compliance: ['NDPR'],
    subfields: ['JAMB', 'WAEC', 'NECO', 'TETFund', 'UBEC'],
    description: 'National examination bodies, tertiary education funding and basic education systems.',
    nigeriaContext: 'JAMB and WAEC portals hold records for millions of candidates annually. Exam portal breaches, result manipulation and credential fraud are documented attack patterns targeting Nigeria\'s education sector.' },
  { id: 'defence',     label: 'Defence & Security',          color: '#CC2B2B', icon: Swords, compliance: ['NDPR', 'ISO 27001', 'NIST SP 800-53'],
    subfields: ['Nigerian Army', 'Nigerian Navy', 'NAF', 'DSA', 'ONSA', 'DIA', 'DSS', 'NIA', 'NCCSALW', 'NPF', 'NSCDC', 'NCS', 'NDLEA', 'EFCC', 'NFIU', 'DICON / NDA / NDC'],
    description: 'Armed forces, intelligence agencies, law enforcement, financial crime units and border security.',
    nigeriaContext: 'DSA and NAF satellite infrastructure are strategic state targets. DSS and NIA systems hold classified intelligence. EFCC and NFIU financial intelligence databases are targeted by organised cybercrime groups disrupting anti-corruption efforts.' },
  { id: 'transport',   label: 'Transport',                   color: '#6366F1', icon: Truck, compliance: ['NDPR', 'ICAO Annex 17'],
    subfields: ['FAAN', 'NCAA', 'NAMA', 'NCAT', 'NiMet', 'AIB', 'NRC', 'NPA', 'NIMASA'],
    description: 'Aviation authority, airspace management, railways, ports and maritime safety infrastructure.',
    nigeriaContext: 'Murtala Muhammed and other international airports handle millions of passengers. NAMA ATC systems and NPA port management are critical chokepoints where cyber disruption carries direct physical-safety consequences.' },
  { id: 'food',        label: 'Food & Agriculture',          color: '#65A30D', icon: Wheat, compliance: ['NDPR'],
    subfields: ['NIRSAL'],
    description: 'Agricultural lending risk systems and national food security infrastructure.',
    nigeriaContext: 'Agriculture employs 36% of Nigerians. NIRSAL digital platforms underpin billions in agricultural credit. Data integrity attacks on lending systems directly impact smallholder farmer access to finance.' },
  { id: 'safety',      label: 'Safety & Emergency Services', color: '#F97316', icon: AlertTriangle, compliance: ['NDPR'],
    subfields: ['NEMA', 'FRSC'],
    description: 'National disaster management and road safety command infrastructure.',
    nigeriaContext: 'NEMA coordinates emergency response during floods, oil spills and security incidents. FRSC systems manage road safety enforcement nationally. Communication disruption during emergencies is a direct life-safety risk.' },
  { id: 'industrial',  label: 'Industrial & Manufacturing',  color: '#78716C', icon: Factory, compliance: ['NDPR', 'ISO 27001'],
    subfields: ['Textile Industry', 'Automobile Sector', 'Other Critical Industrial Sectors'],
    description: 'Critical industrial production sectors including textiles, automotive and strategic manufacturing.',
    nigeriaContext: 'Industrial OT/ICS environments are increasingly networked. Supply chain attacks targeting Nigerian manufacturing are an emerging risk as the sector digitises under the Nigeria Industrial Revolution Plan (NIRP).' },
  { id: 'mines',       label: 'Mines & Steel',               color: '#92400E', icon: Mountain, compliance: ['NDPR'],
    subfields: ['Solid Minerals', 'Ajaokuta Steel Company', 'Major Mines & Steel Entities'],
    description: 'Solid mineral extraction, steel production and major mining infrastructure.',
    nigeriaContext: 'Ajaokuta Steel is a strategic national asset. The Mining Cadastre Office digital platform manages mineral titles. As Nigeria diversifies from oil, solid minerals ICT infrastructure becomes an increasingly attractive target.' },
];

export const SECTOR_BY_ID: Record<string, CniiSector> = Object.fromEntries(CNII_SECTORS.map(s => [s.id, s]));
