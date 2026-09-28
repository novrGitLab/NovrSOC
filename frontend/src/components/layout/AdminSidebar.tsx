'use client';

import {
    LayoutDashboard, FileBarChart, Globe, Users, Shield, UserCheck, Smartphone, Code,
    Crosshair, AlertTriangle, Link as LinkIcon, Building, Building2, Server, Network,
    Mail, MessageSquare, ShieldAlert, Activity, ClipboardList, Zap,
    HardDrive, BarChart, CreditCard, Settings, Database, BookOpen, FileText, ScrollText,
    ClipboardCheck, Bot, Map, Landmark, Radio, Cloud, Eye, Bell, Bug, Monitor, Router, Laptop,
    Droplets, Wifi, HeartPulse, GraduationCap, Swords, Truck, Wheat, Factory, Mountain,
} from 'lucide-react';
import { Sidebar, type NavGroup } from './Sidebar';

// Every href below points at a route that exists. Paths follow the approved route spec after
// the 2026-09-27 cleanup (duplicates removed, misplaced pages moved — e.g. Executive Report is
// /admin/dashboard/executive, Audit Log and Platform Health are under /admin/settings).
//
// `roles` restrictions below (added for the customer-onboarding + multitenancy pass) follow
// that spec's role matrix section-by-section: THREAT INTELLIGENCE, NETWORK,
// INFRASTRUCTURE, and SECURITY OPERATIONS are hidden from `executive`; COMPLIANCE and DATA
// CONTINUITY are hidden from `analyst`; the individually-listed Sec Ops items (Sec Ops
// Management, SOAR Automation) are additionally hidden from `analyst`. OVERVIEW's Dashboard,
// BRAND PROTECTION, EMAIL SECURITY, and AI ANALYST are unrestricted (all four roles), matching
// the matrix's all-✅ rows for those sections.
const NOT_EXEC = ['super_admin', 'soc_manager', 'analyst'] as const;
const MANAGER_PLUS_EXEC = ['super_admin', 'soc_manager', 'executive'] as const;
const MANAGER_ONLY = ['super_admin', 'soc_manager'] as const;

const adminNav: NavGroup[] = [
    {
        section: 'Overview',
        collapsible: true,
        icon: LayoutDashboard,
        groupLabel: 'Overview',
        items: [
            { label: 'Dashboard', href: '/admin/dashboard', icon: LayoutDashboard },
            // "Executive Dashboard" in the role matrix — analyst is the one role that doesn't
            // get this view.
            { label: 'Executive Report', href: '/admin/dashboard/executive', icon: FileBarChart, roles: [...MANAGER_PLUS_EXEC] },
        ],
    },
    {
        section: 'Security Operations',
        collapsible: true,
        icon: Activity,
        groupLabel: 'Security Operations',
        // Incidents were renamed Cases (Supabase case management); /admin/secops/incidents
        // redirects to /admin/secops/cases. Threat Hunting, Shift Handover and Reports are tabs
        // inside Sec Ops Management rather than nav entries.
        //
        // Whole section is executive: ❌ (NOT_EXEC). Sec Ops Management is CISO-only
        // (MANAGER_ONLY: super_admin / soc_manager). SOAR Automation is a read-only report and
        // is visible to analysts, per the SOAR rebuild spec.
        items: [
            { label: 'Cases', href: '/admin/secops/cases', icon: FileText, roles: [...NOT_EXEC] },
            { label: 'Alerts', href: '/admin/secops/alerts', icon: Bell, roles: [...NOT_EXEC] },
            { label: 'Threats', href: '/admin/secops/threats', icon: ShieldAlert, roles: [...NOT_EXEC] },
            { label: 'MITRE Intelligence', href: '/admin/secops/mitre', icon: Shield, roles: [...NOT_EXEC] },
            // Moved from Infrastructure: vulnerabilities are triaged as security work.
            { label: 'Vulnerability Mgmt', href: '/admin/secops/vulnerabilities', icon: Bug, roles: [...NOT_EXEC] },
            { label: 'Playbooks', href: '/admin/secops/playbooks', icon: BookOpen, roles: [...NOT_EXEC] },
            { label: 'SOAR Automation', href: '/admin/secops/soar', icon: Zap, roles: [...NOT_EXEC] },
            { label: 'Security Assessment', href: '/admin/secops/security-assessment', icon: ClipboardCheck, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'Sec Ops Management', href: '/admin/secops/management', icon: Settings, roles: [...MANAGER_ONLY] },
        ],
    },
    {
        section: 'Threat Intelligence',
        collapsible: true,
        icon: Crosshair,
        groupLabel: 'Threat Intelligence',
        // One section for Nigerian and global intelligence (previously two). executive: ❌.
        items: [
            { label: 'Nigeria Threat Map', href: '/admin/threat/nigeria', icon: Map, roles: [...NOT_EXEC] },
            { label: 'Cyber Advisory', href: '/admin/threat/cyber-advisory', icon: Globe, roles: [...NOT_EXEC] },
            { label: 'CBN Advisories', href: '/admin/threat/cbn', icon: Landmark, roles: [...NOT_EXEC] },
            { label: 'NCC Advisories', href: '/admin/threat/ncc', icon: Radio, roles: [...NOT_EXEC] },
            { label: 'Nigeria Deep Dive', href: '/admin/threat/nigeria-deep-dive', icon: Map, roles: [...NOT_EXEC] },
            { label: 'IOC Lookup', href: '/admin/threat/cti', icon: Crosshair, roles: [...NOT_EXEC] },
            // Live IOC Feed is the indicator stream; Threat Feeds is where sources are configured.
            { label: 'Live IOC Feed', href: '/admin/threat/live-ioc', icon: Radio, roles: [...NOT_EXEC] },
            { label: 'Threat Feeds', href: '/admin/threat/feeds', icon: Database, roles: [...NOT_EXEC] },
            { label: 'Threat Advisory', href: '/admin/threat/advisory', icon: AlertTriangle, roles: [...NOT_EXEC] },
            { label: 'Threat Actors', href: '/admin/threat/actors', icon: Users, roles: [...NOT_EXEC] },
            { label: 'URL & Web Scanner', href: '/admin/threat/urlscan', icon: LinkIcon, roles: [...NOT_EXEC] },
            { label: 'Vendor Assessments', href: '/admin/threat/vendor', icon: Building, roles: [...NOT_EXEC] },
        ],
    },
    {
        section: 'CNII Watch',
        collapsible: true,
        icon: Shield,
        groupLabel: 'CNII Watch',
        items: [
            { label: 'Overview', href: '/admin/cnii', icon: LayoutDashboard },
            { label: 'Power & Energy', href: '/admin/cnii/power', icon: Zap },
            { label: 'Water', href: '/admin/cnii/water', icon: Droplets },
            { label: 'ICT & Communications', href: '/admin/cnii/ict', icon: Wifi },
            { label: 'Banking & Finance', href: '/admin/cnii/finance', icon: Landmark },
            { label: 'Health', href: '/admin/cnii/health', icon: HeartPulse },
            { label: 'Public Administration', href: '/admin/cnii/publicadmin', icon: Building },
            { label: 'Education', href: '/admin/cnii/education', icon: GraduationCap },
            { label: 'Defence & Security', href: '/admin/cnii/defence', icon: Swords },
            { label: 'Transport', href: '/admin/cnii/transport', icon: Truck },
            { label: 'Food & Agriculture', href: '/admin/cnii/food', icon: Wheat },
            { label: 'Safety & Emergency', href: '/admin/cnii/safety', icon: AlertTriangle },
            { label: 'Industrial & Mfg', href: '/admin/cnii/industrial', icon: Factory },
            { label: 'Mines & Steel', href: '/admin/cnii/mines', icon: Mountain },
        ],
    },
    {
        section: 'Brand Protection',
        collapsible: true,
        icon: Shield,
        groupLabel: 'Brand Protection',
        items: [
            // Domain Intelligence (one query across domain, DNS and lookalike checks) is the
            // canonical domain page at /admin/brand/domain. /admin/infra/dns stays as the
            // standalone DNS tool.
            { label: 'Domain Intelligence', href: '/admin/brand/domain', icon: Globe },
            { label: 'Social Suite', href: '/admin/brand/social', icon: Users },
            { label: 'Brand Suite', href: '/admin/brand/brand', icon: Shield },
            { label: 'Executive Monitoring', href: '/admin/brand/executive', icon: UserCheck },
            { label: 'Mobile App Suite', href: '/admin/brand/mobile', icon: Smartphone },
            { label: 'Intelli CODE', href: '/admin/brand/copyid', icon: Code },
            { label: 'Dark Web Monitor', href: '/admin/brand/darkweb', icon: Eye },
        ],
    },
    {
        section: 'Network',
        collapsible: true,
        icon: Network,
        groupLabel: 'Network',
        // Network visibility and the sensor setup guides that feed it. executive: ❌.
        items: [
            { label: 'Network Topology', href: '/admin/infra/topology', icon: Network, roles: [...NOT_EXEC] },
            { label: 'Shadow IT', href: '/admin/infra/shadow', icon: Eye, roles: [...NOT_EXEC] },
            { label: 'OPNsense Setup', href: '/admin/infra/opnsense-setup', icon: Router, roles: [...NOT_EXEC] },
            { label: 'Windows (Sysmon)', href: '/admin/infra/sysmon-setup', icon: Monitor, roles: [...NOT_EXEC] },
            { label: 'Mac (osquery)', href: '/admin/infra/osquery-setup', icon: Laptop, roles: [...NOT_EXEC] },
        ],
    },
    {
        section: 'Infrastructure & Assets',
        collapsible: true,
        icon: Server,
        groupLabel: 'Infrastructure & Assets',
        // INFRASTRUCTURE in the matrix — executive: ❌.
        items: [
            { label: 'Digital Assets', href: '/admin/infra/assets', icon: Monitor, roles: [...NOT_EXEC] },
            { label: 'Cloud Assets', href: '/admin/infra/cloud', icon: Cloud, roles: [...NOT_EXEC] },
            { label: 'WebLogic Appliances', href: '/admin/infra/weblogic', icon: Server, roles: [...NOT_EXEC] },
        ],
    },
    {
        section: 'Email Security',
        collapsible: true,
        icon: Mail,
        groupLabel: 'Email Security',
        items: [
            { label: 'Email Monitoring', href: '/admin/email/monitoring', icon: Mail },
            { label: 'DMARC SaaS', href: '/admin/email/dmarc', icon: Mail },
            { label: 'Messaging Suite', href: '/admin/email/messaging', icon: MessageSquare },
            { label: 'PHISHID', href: '/admin/email/phishid', icon: ShieldAlert },
            { label: 'Email Investigation', href: '/admin/email/investigate', icon: Crosshair },
        ],
    },
    {
        section: 'Compliance',
        collapsible: true,
        icon: ClipboardCheck,
        groupLabel: 'Compliance',
        // COMPLIANCE in the matrix — analyst: ❌.
        items: [
            { label: 'Compliance Dashboard', href: '/admin/compliance', icon: ClipboardCheck, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'NDPA', href: '/admin/compliance/ndpa', icon: FileText, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'ISO 27001', href: '/admin/compliance/iso27001', icon: FileText, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'CBN Framework', href: '/admin/compliance/cbn', icon: FileText, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'PCI-DSS', href: '/admin/compliance/pcidss', icon: FileText, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'NCC Framework', href: '/admin/compliance/ncc', icon: FileText, roles: [...MANAGER_PLUS_EXEC] },
        ],
    },
    {
        section: 'AI Analyst',
        collapsible: true,
        icon: Bot,
        groupLabel: 'AI Analyst',
        items: [
            { label: 'NovrAI', href: '/admin/novrail', icon: Bot },
        ],
    },
    {
        section: 'Data Continuity',
        collapsible: true,
        icon: HardDrive,
        groupLabel: 'Data Continuity',
        // DATA CONTINUITY in the matrix — analyst: ❌.
        items: [
            { label: 'Data Loss Recovery', href: '/admin/data/recovery', icon: HardDrive, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'Recovery Credit', href: '/admin/data/sla', icon: BarChart, roles: [...MANAGER_PLUS_EXEC] },
            { label: 'Disaster Recovery Plan', href: '/admin/data/drp', icon: ClipboardList, roles: [...MANAGER_PLUS_EXEC] },
        ],
    },
    {
        section: 'Customers',
        collapsible: true,
        icon: Building2,
        groupLabel: 'Customers',
        items: [
            { label: 'All Customers', href: '/admin/customers', icon: Building2, adminOnly: true },
        ],
    },
    {
        section: 'Settings',
        collapsible: true,
        icon: Settings,
        groupLabel: 'Settings',
        items: [
            { label: 'Team', href: '/admin/settings/team', icon: Users, adminOnly: true },
            { label: 'Organisations', href: '/admin/settings/organisations', icon: Building2, adminOnly: true },
            { label: 'Billing', href: '/admin/settings/billing', icon: CreditCard, adminOnly: true },
            { label: 'Analytics', href: '/admin/settings/analytics', icon: BarChart, adminOnly: true },
            { label: 'Audit Log', href: '/admin/settings/audit', icon: ScrollText, adminOnly: true },
            { label: 'Platform Health', href: '/admin/settings/health', icon: Activity, managerOnly: true },
        ],
    },
];

interface AdminSidebarProps {
    user: { name: string; email: string; role: string };
    onLogout: () => void;
}

export function AdminSidebar({ user, onLogout }: AdminSidebarProps) {
    return <Sidebar navGroups={adminNav} user={user} onLogout={onLogout} />;
}
