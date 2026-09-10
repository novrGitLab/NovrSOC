'use client';

import {
    LayoutDashboard, FileBarChart, Globe, Users, Shield, UserCheck, Smartphone, Code,
    Crosshair, AlertTriangle, Link as LinkIcon, Building, Building2, Server, Network, Cpu,
    Mail, MessageSquare, ShieldAlert, Activity, Siren, ClipboardList, Zap,
    HardDrive, BarChart, CreditCard, Settings, Database, BookOpen, FileText, ScrollText,
    ClipboardCheck, Bot, WifiOff, Map, Landmark, Radio, Wrench,
} from 'lucide-react';
import { Sidebar, type NavGroup } from './Sidebar';

// Reorganised per the platform-wide nav restructure. Every href below points at a route that
// actually exists (either pre-existing or newly built alongside this reorg) — several of the
// requested paths in the original spec didn't match this codebase's real routes (e.g. IOC
// Lookup is /admin/threat/cti not /admin/threat/ioc-lookup, URL Scanner is
// /admin/threat/urlscan not /admin/threat/url) and were kept at their real, working paths
// rather than moved, since renaming a route breaks bookmarks/links for no benefit.
//
// `roles` restrictions below (added for the customer-onboarding + multitenancy pass) follow
// that spec's role matrix section-by-section: THREAT INTELLIGENCE (both threat-intel groups),
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
            { label: 'Executive Report', href: '/admin/executive', icon: FileBarChart, roles: [...MANAGER_PLUS_EXEC] },
        ],
    },
    {
        section: 'Security Operations',
        collapsible: true,
        icon: Activity,
        groupLabel: 'Security Operations',
        // Cases, Threat Hunting, Shift Handover, and Reports Center are off the nav per the
        // Security Operations redesign — moved into Security Ops Management as tabs (Threat
        // Hunting, Shift Handover, Reports) or, for Cases, just no longer linked (TheHive case
        // management isn't surfaced to analysts as a separate concept from Incidents — see
        // CasesPage.tsx). All four routes still work if visited directly; nothing was deleted.
        //
        // Whole section is executive: ❌ (NOT_EXEC on every item); Sec Ops Mgmt and SOAR are
        // additionally analyst: ❌ (MANAGER_ONLY) per the matrix's per-item breakdown.
        items: [
            { label: 'Incidents', href: '/admin/secops/incidents', icon: Siren, roles: [...NOT_EXEC] },
            { label: 'Alerts', href: '/admin/secops/alerts', icon: Activity, roles: [...NOT_EXEC] },
            { label: 'Security Ops Mgmt', href: '/admin/secops/management', icon: Wrench, roles: [...MANAGER_ONLY] },
            { label: 'Playbooks', href: '/admin/secops/playbooks', icon: BookOpen, roles: [...NOT_EXEC] },
            { label: 'SOAR Automation', href: '/admin/secops/soar', icon: Zap, roles: [...MANAGER_ONLY] },
        ],
    },
    {
        section: 'Nigerian Threat Intel',
        collapsible: true,
        icon: Globe,
        groupLabel: 'Nigerian Threat Intel',
        // THREAT INTELLIGENCE in the matrix covers both this section and Global Threat Intel
        // below — executive: ❌ on both.
        items: [
            { label: 'Nigeria Threat Map', href: '/admin/threat/nigeria-map', icon: Map, roles: [...NOT_EXEC] },
            { label: 'Nigerian Threat Feed', href: '/admin/threat/nigeria', icon: Globe, roles: [...NOT_EXEC] },
            { label: 'CBN Advisories', href: '/admin/threat/cbn', icon: Landmark, roles: [...NOT_EXEC] },
            { label: 'NCC Advisories', href: '/admin/threat/ncc', icon: Radio, roles: [...NOT_EXEC] },
        ],
    },
    {
        section: 'Global Threat Intel',
        collapsible: true,
        icon: Crosshair,
        groupLabel: 'Global Threat Intel',
        items: [
            { label: 'IOC Lookup', href: '/admin/threat/cti', icon: Crosshair, roles: [...NOT_EXEC] },
            { label: 'Threat Feeds', href: '/admin/threat/feeds', icon: Database, roles: [...NOT_EXEC] },
            { label: 'MITRE ATT&CK', href: '/admin/threat/mitre', icon: ShieldAlert, roles: [...NOT_EXEC] },
            { label: 'Threat Advisory', href: '/admin/threat/advisory', icon: AlertTriangle, roles: [...NOT_EXEC] },
            { label: 'Threat Actors', href: '/admin/threat/actors', icon: Users, roles: [...NOT_EXEC] },
            { label: 'URL & Web Scanner', href: '/admin/threat/scanner', icon: LinkIcon, roles: [...NOT_EXEC] },
            { label: 'Vendor Assessments', href: '/admin/threat/vendor', icon: Building, roles: [...NOT_EXEC] },
        ],
    },
    {
        section: 'Brand Protection',
        collapsible: true,
        icon: Shield,
        groupLabel: 'Brand Protection',
        items: [
            // Replaces the old 'Domain & DNS Suite' entry, which pointed at two separate tools
            // behind a tab switch (each with its own input). /admin/brand/domain-dns and the
            // individual /admin/brand/domain and /admin/infra/dns routes all still resolve —
            // only the nav entry moved, so existing links and bookmarks don't break.
            { label: 'Domain Intelligence', href: '/admin/brand/domain-intelligence', icon: Globe },
            { label: 'Social Suite', href: '/admin/brand/social', icon: Users },
            { label: 'Brand Suite', href: '/admin/brand/brand', icon: Shield },
            { label: 'Executive Monitoring', href: '/admin/brand/executive', icon: UserCheck },
            { label: 'Mobile App Suite', href: '/admin/brand/mobile', icon: Smartphone },
            { label: 'Intelli CODE', href: '/admin/brand/copyid', icon: Code },
        ],
    },
    {
        section: 'Infrastructure & Assets',
        collapsible: true,
        icon: Server,
        groupLabel: 'Infrastructure & Assets',
        // INFRASTRUCTURE in the matrix — executive: ❌.
        items: [
            { label: 'Digital Assets', href: '/admin/infra/assets', icon: Server, roles: [...NOT_EXEC] },
            { label: 'Network Topology', href: '/admin/infra/topology', icon: Network, roles: [...NOT_EXEC] },
            { label: 'Vulnerability Management', href: '/admin/infra/vulnerabilities', icon: ShieldAlert, roles: [...NOT_EXEC] },
            { label: 'WebLogic Appliances', href: '/admin/infra/weblogic', icon: Cpu, roles: [...NOT_EXEC] },
            { label: 'Shadow IT', href: '/admin/infra/shadow', icon: WifiOff, roles: [...NOT_EXEC] },
        ],
    },
    {
        section: 'Email Security',
        collapsible: true,
        icon: Mail,
        groupLabel: 'Email Security',
        items: [
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
            { label: 'NovrAI Chat', href: '/admin/novrail', icon: Bot },
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
            { label: 'Disaster Recovery Plan', href: '/admin/data/recovery-plan', icon: ClipboardList, roles: [...MANAGER_PLUS_EXEC] },
        ],
    },
    {
        section: 'Customers',
        collapsible: true,
        icon: Building2,
        groupLabel: 'Customers',
        items: [
            { label: 'All Customers', href: '/admin/customers', icon: Building2, adminOnly: true },
            { label: 'Client Portals', href: '/admin/platform/clients', icon: Building2, adminOnly: true },
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
            { label: 'Audit Log', href: '/admin/platform/audit', icon: ScrollText, adminOnly: true },
            { label: 'Platform Health', href: '/admin/platform/health', icon: Activity, managerOnly: true },
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
