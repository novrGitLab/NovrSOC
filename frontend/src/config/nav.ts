// Single source of truth for the admin and client sidebars.
//
// Each item carries:
//   id       stable identifier (also used by scripts/check-nav-routes.mjs in reports)
//   label    text shown in the sidebar
//   href     route; must resolve to a page under src/app (enforced by `npm run check:nav`)
//   domain   product area the item belongs to
//   status   implementation status, using the audit's labels (docs/audit/NOVRSOC_AUDIT.md),
//            updated for the 2026-10 cleanup: WORKING, PARTIAL, MOCK, BROKEN, PLANNED.
//            Metadata only — the sidebar does not display it.
//   roles    'all' (every authenticated role, no filter) or an explicit allow-list.
//
// Sidebar.tsx's own role filter is unchanged: `roles: 'all'` maps to "no roles field" (visible
// to any role, as before), and an explicit list maps to NavItem.roles. The previous adminOnly
// flag equals ['super_admin'] and managerOnly equals ['super_admin', 'soc_manager'].
//
// v2 features (Mobile Application Security, Code Security, Shadow IT) are not listed in the
// admin nav. Their pages may still exist; they are simply not linked.
import {
    LayoutDashboard, FileBarChart, Globe, Users, Shield, UserCheck, Smartphone, Code,
    Crosshair, AlertTriangle, Link as LinkIcon, Building, Building2, Server, Network,
    Mail, MessageSquare, ShieldAlert, Activity, Zap, Siren,
    HardDrive, BarChart, CreditCard, Settings, BookOpen, FileText, ScrollText,
    ClipboardCheck, Bot, Map, Landmark, Radio, Cloud, Eye, Bell, Bug, Monitor,
    Droplets, Wifi, HeartPulse, GraduationCap, Swords, Truck, Wheat, Factory, Mountain,
    type LucideIcon,
} from 'lucide-react';
import type { NavGroup, NavItem, NavRole } from '@/components/layout/Sidebar';

export type NavStatus = 'WORKING' | 'PARTIAL' | 'MOCK' | 'BROKEN' | 'PLANNED';
export type NavDomain =
    | 'overview' | 'secops' | 'threat-intel' | 'cnii' | 'brand' | 'infra' | 'email'
    | 'compliance' | 'ai' | 'data' | 'clients' | 'settings' | 'account';

export interface NavItemConfig {
    id: string;
    label: string;
    href: string;
    domain: NavDomain;
    status: NavStatus;
    roles: 'all' | NavRole[];
    icon: LucideIcon;
}

export interface NavSectionConfig {
    section: string;
    collapsible: boolean;
    icon?: LucideIcon;
    groupLabel?: string;
    items: NavItemConfig[];
}

const NOT_EXEC: NavRole[] = ['super_admin', 'soc_manager', 'analyst'];
const MANAGER_PLUS_EXEC: NavRole[] = ['super_admin', 'soc_manager', 'executive'];
const MANAGER_ONLY: NavRole[] = ['super_admin', 'soc_manager'];
const SUPER_ADMIN: NavRole[] = ['super_admin'];

const CNII_SECTORS: [string, string, LucideIcon][] = [
    ['power', 'Power & Energy', Zap],
    ['water', 'Water', Droplets],
    ['ict', 'ICT & Communications', Wifi],
    ['finance', 'Banking & Finance', Landmark],
    ['health', 'Health', HeartPulse],
    ['publicadmin', 'Public Administration', Building],
    ['education', 'Education', GraduationCap],
    ['defence', 'Defence & Security', Swords],
    ['transport', 'Transport', Truck],
    ['food', 'Food & Agriculture', Wheat],
    ['safety', 'Safety & Emergency', AlertTriangle],
    ['industrial', 'Industrial & Mfg', Factory],
    ['mines', 'Mines & Steel', Mountain],
];

export const ADMIN_NAV: NavSectionConfig[] = [
    {
        section: 'Overview', collapsible: true, icon: LayoutDashboard, groupLabel: 'Overview',
        items: [
            { id: 'dashboard', label: 'Dashboard', href: '/admin/dashboard', domain: 'overview', status: 'PARTIAL', roles: 'all', icon: LayoutDashboard },
            { id: 'executive-report', label: 'Executive Report', href: '/admin/dashboard/executive', domain: 'overview', status: 'WORKING', roles: MANAGER_PLUS_EXEC, icon: FileBarChart },
        ],
    },
    {
        // executive: hidden. Sec Ops Management is manager-only.
        section: 'Security Operations', collapsible: true, icon: Activity, groupLabel: 'Security Operations',
        items: [
            { id: 'cases', label: 'Cases', href: '/admin/secops/cases', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: FileText },
            { id: 'alerts', label: 'Alerts', href: '/admin/secops/alerts', domain: 'secops', status: 'PARTIAL', roles: NOT_EXEC, icon: Bell },
            { id: 'threats', label: 'Threats', href: '/admin/secops/threats', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: ShieldAlert },
            { id: 'mitre', label: 'MITRE Intelligence', href: '/admin/secops/mitre', domain: 'secops', status: 'PARTIAL', roles: NOT_EXEC, icon: Shield },
            { id: 'vulnerabilities', label: 'Vulnerability Mgmt', href: '/admin/secops/vulnerabilities', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: Bug },
            { id: 'playbooks', label: 'Playbooks', href: '/admin/secops/playbooks', domain: 'secops', status: 'PARTIAL', roles: NOT_EXEC, icon: BookOpen },
            { id: 'soar', label: 'SOAR Automation', href: '/admin/secops/soar', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: Zap },
            { id: 'security-assessment', label: 'Security Assessment', href: '/admin/secops/security-assessment', domain: 'secops', status: 'WORKING', roles: MANAGER_PLUS_EXEC, icon: ClipboardCheck },
            { id: 'secops-management', label: 'Sec Ops Management', href: '/admin/secops/management', domain: 'secops', status: 'PARTIAL', roles: MANAGER_ONLY, icon: Settings },
        ],
    },
    {
        section: 'Threat Intelligence', collapsible: true, icon: Crosshair, groupLabel: 'Threat Intelligence',
        items: [
            { id: 'nigeria-threat-map', label: 'Nigeria Threat Map', href: '/admin/threat/nigeria', domain: 'threat-intel', status: 'PARTIAL', roles: NOT_EXEC, icon: Map },
            { id: 'ioc-lookup', label: 'IOC Lookup', href: '/admin/threat/cti', domain: 'threat-intel', status: 'PARTIAL', roles: NOT_EXEC, icon: Crosshair },
            { id: 'live-ioc', label: 'Live IOC Feed', href: '/admin/threat/live-ioc', domain: 'threat-intel', status: 'WORKING', roles: NOT_EXEC, icon: Radio },
            { id: 'threat-advisory', label: 'Threat Advisory', href: '/admin/threat/advisory', domain: 'threat-intel', status: 'WORKING', roles: NOT_EXEC, icon: AlertTriangle },
            { id: 'threat-actors', label: 'Threat Actors', href: '/admin/threat/actors', domain: 'threat-intel', status: 'WORKING', roles: NOT_EXEC, icon: Users },
            { id: 'url-web-scanner', label: 'URL & Web Scanner', href: '/admin/threat/urlscan', domain: 'threat-intel', status: 'WORKING', roles: NOT_EXEC, icon: LinkIcon },
        ],
    },
    {
        // CNII alerts are "not connected" since Wazuh was decoupled, hence PARTIAL.
        section: 'CNII Watch', collapsible: true, icon: Shield, groupLabel: 'CNII Watch',
        items: [
            { id: 'cnii-overview', label: 'Overview', href: '/admin/cnii', domain: 'cnii', status: 'PARTIAL', roles: 'all', icon: LayoutDashboard },
            ...CNII_SECTORS.map(([slug, label, icon]): NavItemConfig => (
                { id: `cnii-${slug}`, label, href: `/admin/cnii/${slug}`, domain: 'cnii', status: 'PARTIAL', roles: 'all', icon }
            )),
        ],
    },
    {
        // Mobile App Suite and Intelli CODE (Mobile Application / Code Security) are v2 and not listed.
        section: 'Brand Protection', collapsible: true, icon: Shield, groupLabel: 'Brand Protection',
        items: [
            { id: 'domain-intelligence', label: 'Domain Intelligence', href: '/admin/brand/domain', domain: 'brand', status: 'PARTIAL', roles: 'all', icon: Globe },
            { id: 'social-suite', label: 'Social Suite', href: '/admin/brand/social', domain: 'brand', status: 'PARTIAL', roles: 'all', icon: Users },
            { id: 'brand-suite', label: 'Brand Suite', href: '/admin/brand/brand', domain: 'brand', status: 'PARTIAL', roles: 'all', icon: Shield },
            { id: 'executive-monitoring', label: 'Executive Monitoring', href: '/admin/brand/executive', domain: 'brand', status: 'PARTIAL', roles: 'all', icon: UserCheck },
            { id: 'dark-web', label: 'Dark Web Monitor', href: '/admin/brand/darkweb', domain: 'brand', status: 'WORKING', roles: 'all', icon: Eye },
        ],
    },
    {
        section: 'Infrastructure & Assets', collapsible: true, icon: Server, groupLabel: 'Infrastructure & Assets',
        items: [
            { id: 'digital-assets', label: 'Digital Assets', href: '/admin/infra/assets', domain: 'infra', status: 'WORKING', roles: NOT_EXEC, icon: Monitor },
            { id: 'cloud-assets', label: 'Cloud Assets', href: '/admin/infra/cloud', domain: 'infra', status: 'PARTIAL', roles: NOT_EXEC, icon: Cloud },
        ],
    },
    {
        section: 'Email Security', collapsible: true, icon: Mail, groupLabel: 'Email Security',
        items: [
            { id: 'email-overview', label: 'Overview', href: '/admin/email', domain: 'email', status: 'WORKING', roles: 'all', icon: LayoutDashboard },
            { id: 'dmarc', label: 'DMARC SaaS', href: '/admin/email/dmarc', domain: 'email', status: 'WORKING', roles: 'all', icon: Mail },
            { id: 'phish-id', label: 'Intellicode Phish ID', href: '/admin/email/phishid', domain: 'email', status: 'WORKING', roles: 'all', icon: ShieldAlert },
            { id: 'messaging', label: 'Messaging Suite', href: '/admin/email/messaging', domain: 'email', status: 'WORKING', roles: 'all', icon: MessageSquare },
            { id: 'email-setup', label: 'Setup & Configuration', href: '/admin/email/setup', domain: 'email', status: 'WORKING', roles: 'all', icon: Settings },
        ],
    },
    {
        // CBN and NCC have no compliance_frameworks row, so assessments cannot be recorded.
        section: 'Compliance', collapsible: true, icon: ClipboardCheck, groupLabel: 'Compliance',
        items: [
            { id: 'compliance-dashboard', label: 'Compliance Dashboard', href: '/admin/compliance', domain: 'compliance', status: 'PARTIAL', roles: MANAGER_PLUS_EXEC, icon: ClipboardCheck },
            { id: 'ndpa', label: 'NDPA', href: '/admin/compliance/ndpa', domain: 'compliance', status: 'PARTIAL', roles: MANAGER_PLUS_EXEC, icon: FileText },
            { id: 'iso27001', label: 'ISO 27001', href: '/admin/compliance/iso27001', domain: 'compliance', status: 'PARTIAL', roles: MANAGER_PLUS_EXEC, icon: FileText },
            { id: 'cbn', label: 'CBN Framework', href: '/admin/compliance/cbn', domain: 'compliance', status: 'BROKEN', roles: MANAGER_PLUS_EXEC, icon: FileText },
            { id: 'pcidss', label: 'PCI-DSS', href: '/admin/compliance/pcidss', domain: 'compliance', status: 'PARTIAL', roles: MANAGER_PLUS_EXEC, icon: FileText },
            { id: 'ncc', label: 'NCC Framework', href: '/admin/compliance/ncc', domain: 'compliance', status: 'BROKEN', roles: MANAGER_PLUS_EXEC, icon: FileText },
        ],
    },
    {
        section: 'AI Analyst', collapsible: true, icon: Bot, groupLabel: 'AI Analyst',
        items: [
            { id: 'novrai', label: 'NovrAI', href: '/admin/novrail', domain: 'ai', status: 'PARTIAL', roles: 'all', icon: Bot },
        ],
    },
    {
        section: 'Data Continuity', collapsible: true, icon: HardDrive, groupLabel: 'Data Continuity',
        items: [
            { id: 'data-loss-recovery', label: 'Data Loss Recovery', href: '/admin/data/recovery', domain: 'data', status: 'PARTIAL', roles: MANAGER_PLUS_EXEC, icon: HardDrive },
        ],
    },
    {
        section: 'Clients', collapsible: true, icon: Building2, groupLabel: 'Clients',
        items: [
            { id: 'all-clients', label: 'All Clients', href: '/admin/customers', domain: 'clients', status: 'WORKING', roles: SUPER_ADMIN, icon: Building2 },
        ],
    },
    {
        section: 'Settings', collapsible: true, icon: Settings, groupLabel: 'Settings',
        items: [
            { id: 'team', label: 'Team', href: '/admin/settings/team', domain: 'settings', status: 'WORKING', roles: SUPER_ADMIN, icon: Users },
            { id: 'billing', label: 'Billing', href: '/admin/settings/billing', domain: 'settings', status: 'PARTIAL', roles: SUPER_ADMIN, icon: CreditCard },
            { id: 'analytics', label: 'Analytics', href: '/admin/settings/analytics', domain: 'settings', status: 'WORKING', roles: SUPER_ADMIN, icon: BarChart },
            { id: 'audit-log', label: 'Audit Log', href: '/admin/settings/audit', domain: 'settings', status: 'PARTIAL', roles: SUPER_ADMIN, icon: ScrollText },
            { id: 'platform-health', label: 'Platform Health', href: '/admin/settings/health', domain: 'settings', status: 'WORKING', roles: MANAGER_ONLY, icon: Activity },
        ],
    },
];

// Client portal. Every item is BROKEN at the portal level: portal sign-in depends on the
// unreachable APP_API_BASE_URL backend, so no customer can reach these pages today.
export const CLIENT_NAV: NavSectionConfig[] = [
    {
        section: '', collapsible: false,
        items: [
            { id: 'client-dashboard', label: 'Dashboard', href: '/client/dashboard', domain: 'overview', status: 'BROKEN', roles: 'all', icon: LayoutDashboard },
        ],
    },
    {
        section: 'Brand Protection', collapsible: true, icon: Shield, groupLabel: 'Brand Protection',
        items: [
            { id: 'client-domain-suite', label: 'Domain Suite', href: '/client/brand/domain', domain: 'brand', status: 'BROKEN', roles: 'all', icon: Globe },
            { id: 'client-social-suite', label: 'Social Suite', href: '/client/brand/social', domain: 'brand', status: 'BROKEN', roles: 'all', icon: Users },
            { id: 'client-brand-suite', label: 'Brand Suite', href: '/client/brand/brand', domain: 'brand', status: 'BROKEN', roles: 'all', icon: Shield },
            { id: 'client-executive-monitor', label: 'Executive Monitor', href: '/client/brand/executive', domain: 'brand', status: 'BROKEN', roles: 'all', icon: UserCheck },
            { id: 'client-mobile-app-suite', label: 'Mobile App Suite', href: '/client/brand/mobile', domain: 'brand', status: 'BROKEN', roles: 'all', icon: Smartphone },
            { id: 'client-intelli-code', label: 'Intelli CODE copyID', href: '/client/brand/copyid', domain: 'brand', status: 'BROKEN', roles: 'all', icon: Code },
        ],
    },
    {
        section: 'Threat Intelligence', collapsible: true, icon: Crosshair, groupLabel: 'Threat Intelligence',
        items: [
            { id: 'client-cti', label: 'CTI Platform', href: '/client/threat/cti', domain: 'threat-intel', status: 'BROKEN', roles: 'all', icon: Crosshair },
            { id: 'client-threat-advisory', label: 'Threat Advisory', href: '/client/threat/advisory', domain: 'threat-intel', status: 'BROKEN', roles: 'all', icon: AlertTriangle },
            { id: 'client-urlscan', label: 'URL Scan Suite', href: '/client/threat/urlscan', domain: 'threat-intel', status: 'BROKEN', roles: 'all', icon: LinkIcon },
            { id: 'client-webscan', label: 'Website Scanning', href: '/client/threat/webscan', domain: 'threat-intel', status: 'BROKEN', roles: 'all', icon: Monitor },
        ],
    },
    {
        section: 'Infrastructure', collapsible: true, icon: Server, groupLabel: 'Infrastructure',
        items: [
            { id: 'client-digital-assets', label: 'Digital Assets', href: '/client/infra/assets', domain: 'infra', status: 'BROKEN', roles: 'all', icon: Server },
            { id: 'client-dns', label: 'DNS Suite', href: '/client/infra/dns', domain: 'infra', status: 'BROKEN', roles: 'all', icon: Network },
        ],
    },
    {
        section: 'SecOps & Response', collapsible: true, icon: Activity, groupLabel: 'SecOps & Response',
        items: [
            { id: 'client-threat-management', label: 'Threat Management', href: '/client/secops/threats', domain: 'secops', status: 'BROKEN', roles: 'all', icon: Activity },
            { id: 'client-cases', label: 'Cases', href: '/client/secops/cases', domain: 'secops', status: 'BROKEN', roles: 'all', icon: Siren },
            { id: 'client-report-card', label: 'Security Report Card', href: '/client/secops/security-assessment', domain: 'secops', status: 'BROKEN', roles: 'all', icon: Activity },
            { id: 'client-alert-communication', label: 'Alert Communication', href: '/client/secops/alerts', domain: 'secops', status: 'BROKEN', roles: 'all', icon: Bell },
        ],
    },
    {
        section: 'Data Continuity', collapsible: true, icon: HardDrive, groupLabel: 'Data Continuity',
        items: [
            { id: 'client-data-loss-recovery', label: 'Data Loss Recovery', href: '/client/data/recovery', domain: 'data', status: 'BROKEN', roles: 'all', icon: HardDrive },
        ],
    },
    {
        section: 'Account', collapsible: false,
        items: [
            { id: 'client-billing', label: 'Billing & Subscription', href: '/client/billing', domain: 'account', status: 'BROKEN', roles: 'all', icon: CreditCard },
        ],
    },
];

/** Converts config sections into the NavGroup shape Sidebar.tsx renders. */
export function toNavGroups(sections: NavSectionConfig[]): NavGroup[] {
    return sections.map(({ items, ...section }) => ({
        ...section,
        items: items.map(({ label, href, icon, roles }): NavItem => (roles === 'all' ? { label, href, icon } : { label, href, icon, roles })),
    }));
}

/** Every href in both navs — used by scripts/check-nav-routes.mjs. */
export const ALL_NAV_HREFS: string[] = [...ADMIN_NAV, ...CLIENT_NAV].flatMap((s) => s.items.map((i) => i.href));
