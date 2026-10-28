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
    Crosshair, AlertTriangle, Link as LinkIcon, Building, Building2, Server, Network, ShieldCheck, Radar,
    Mail, MessageSquare, ShieldAlert, Activity, Zap, Siren,
    HardDrive, BarChart, CreditCard, Settings, BookOpen, FileText, ScrollText,
    ClipboardCheck, Bot, Map, Landmark, Radio, Cloud, Eye, Bell, Monitor,
    Target, Fingerprint, CalendarRange, Droplets, Wifi, HeartPulse, GraduationCap, Swords, Truck, Wheat, Factory, Mountain, KeyRound,
    Sparkles,
    type LucideIcon,
} from 'lucide-react';
import type { NavGroup, NavItem, NavRole } from '@/components/layout/Sidebar';
import { VMS_SECTIONS } from './vmsSections';

export type NavStatus = 'WORKING' | 'PARTIAL' | 'MOCK' | 'BROKEN' | 'PLANNED';
export type NavDomain =
    | 'overview' | 'secops' | 'vms' | 'threat-intel' | 'cnii' | 'brand' | 'infra' | 'email'
    | 'compliance' | 'ai' | 'data' | 'clients' | 'settings' | 'account' | 'reports' | 'collectors';

export interface NavItemConfig {
    id: string;
    label: string;
    href: string;
    domain: NavDomain;
    status: NavStatus;
    roles: 'all' | NavRole[];
    icon: LucideIcon;
    /** Sub-page route prefixes that keep this item highlighted (see Sidebar isNavItemActive). */
    match?: string[];
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
// VMS is readable by executives too (their organisation's attack surface and risk).
/** VMS_READ also gates the Threat Information System: the backend's vms:read and intel:read go to the same roles. */
const VMS_READ: NavRole[] = ['super_admin', 'soc_manager', 'analyst', 'executive'];

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
        // Reporting Center (phase P30, R3.3E): schedule/recipient administration and generate-now
        // need reports:manage (not executive — recipient management can add an external email
        // address); viewing uses reports:read, held by the same roles as VMS_READ.
        section: 'Reporting Center', collapsible: true, icon: FileBarChart, groupLabel: 'Reporting Center',
        items: [
            { id: 'reporting-center', label: 'Reporting Center', href: '/admin/reports', domain: 'reports', status: 'WORKING', roles: VMS_READ, icon: FileBarChart },
        ],
    },
    {
        // Collector Management (phase P31, Collector V1): manager-tier infrastructure access — a
        // collector's credential reaches live client-site log plumbing, closer to Wazuh Groups /
        // Sec Ops Management than to day-to-day SOC analysis. Not analyst, executive or
        // portal_user — matches the backend's collectors:read/collectors:manage exactly.
        section: 'Collector Management', collapsible: true, icon: Server, groupLabel: 'Collector Management',
        items: [
            { id: 'collector-management', label: 'Collector Management', href: '/admin/collectors', domain: 'collectors', status: 'WORKING', roles: MANAGER_ONLY, icon: Server },
        ],
    },
    {
        // executive: hidden. Sec Ops Management is manager-only.
        section: 'Security Operations', collapsible: true, icon: Activity, groupLabel: 'Security Operations',
        items: [
            { id: 'cases', label: 'Cases', href: '/admin/secops/cases', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: FileText },
            { id: 'alerts', label: 'Alerts', href: '/admin/secops/alerts', domain: 'secops', status: 'PARTIAL', roles: NOT_EXEC, icon: Bell },
            // Had no nav entry at all (audit F-xx, §4 "pages not reachable from any navigation");
            // both call real, tested backend routes (/api/communications/*, /api/secops/hunting/
            // escalate, /api/wazuh/hunt) and are not duplicates of anything else in this section.
            { id: 'alert-comms', label: 'Alert Communication', href: '/admin/secops/alert-comms', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: MessageSquare },
            { id: 'threats', label: 'Threats', href: '/admin/secops/threats', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: ShieldAlert },
            { id: 'hunting', label: 'Threat Hunting', href: '/admin/secops/hunting', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: Crosshair },
            { id: 'wazuh-vulnerabilities', label: 'Wazuh Vulnerabilities', href: '/admin/secops/vulnerabilities', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: AlertTriangle },
            { id: 'mitre', label: 'MITRE Intelligence', href: '/admin/secops/mitre', domain: 'secops', status: 'PARTIAL', roles: NOT_EXEC, icon: Shield },
            { id: 'playbooks', label: 'Playbooks', href: '/admin/secops/playbooks', domain: 'secops', status: 'PARTIAL', roles: NOT_EXEC, icon: BookOpen },
            { id: 'soar', label: 'SOAR Automation', href: '/admin/secops/soar', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: Zap },
            { id: 'response-approvals', label: 'Response Approvals', href: '/admin/secops/approvals', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: ShieldCheck },
            { id: 'weekly-insights', label: 'Weekly Insights', href: '/admin/secops/insights', domain: 'secops', status: 'WORKING', roles: NOT_EXEC, icon: CalendarRange },
            // R3.3C: staff-only, not MANAGER_PLUS_EXEC — this page's backend (GET /api/admin/
            // security-assessment/overview) has no per-caller org filter; it returns every
            // active client organisation's posture. An executive's own org is served correctly
            // by the client-report-card entry below.
            { id: 'security-assessment', label: 'Security Assessment', href: '/admin/secops/security-assessment', domain: 'secops', status: 'WORKING', roles: ['super_admin', 'soc_manager'], icon: ClipboardCheck },
            { id: 'secops-management', label: 'Sec Ops Management', href: '/admin/secops/management', domain: 'secops', status: 'PARTIAL', roles: MANAGER_ONLY, icon: Settings },
        ],
    },
    {
        // VMS redesign (P20): eight sections; each section's pages are tabs in app/admin/vms/layout.tsx
        // (config/vmsSections.ts). Scanner Operations is for managers — the backend enforces it
        // (its data comes from vms:scope endpoints), not only this list.
        section: 'Vulnerability Management', collapsible: true, icon: Radar, groupLabel: 'Vulnerability Management',
        items: VMS_SECTIONS.map((s): NavItemConfig => ({ id: `vms-${s.id}`, label: s.label, href: s.href, domain: 'vms', status: 'WORKING', roles: s.managerOnly ? MANAGER_ONLY : VMS_READ, icon: s.icon, match: s.pages.map((p) => p.href).filter((h) => h !== '/admin/vms') })),
    },
    {
        // Threat Intelligence V1 (P25): eight pages. The external IOC lookup and the URL & web
        // scanner are tools linked from Indicators & Investigation; the older pages redirect here.
        section: 'Threat Intelligence', collapsible: true, icon: Crosshair, groupLabel: 'Threat Intelligence',
        items: [
            { id: 'ti-overview', label: 'Overview', href: '/admin/ti', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: Crosshair },
            { id: 'ti-map', label: 'Nigeria Threat Map', href: '/admin/ti/map', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: Map },
            { id: 'ti-indicators', label: 'Indicators & Investigation', href: '/admin/ti/indicators', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: Fingerprint, match: ['/admin/threat/cti', '/admin/threat/urlscan', '/admin/threat/webscan'] },
            { id: 'ti-actors', label: 'Threat Actors', href: '/admin/ti/actors', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: Users },
            { id: 'ti-matches', label: 'Organisation Matches', href: '/admin/ti/matches', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: Target },
            { id: 'ti-vulnerabilities', label: 'Vulnerabilities & Advisories', href: '/admin/ti/vulnerabilities', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: ShieldAlert },
            { id: 'ti-analyst', label: 'AI Intelligence Analyst', href: '/admin/ti/analyst', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: Sparkles },
            { id: 'ti-sources', label: 'Sources & Exchange', href: '/admin/ti/sources', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: Radio },
            { id: 'ti-report', label: 'Reports', href: '/admin/ti/report', domain: 'threat-intel', status: 'WORKING', roles: VMS_READ, icon: FileBarChart },
        ],
    },
    {
        // Phase P9: a sector view over VMS and the Threat Information System. Sector pages read
        // across organisations, so they are for SOC staff; an executive sees only their own
        // organisation. PARTIAL until the P9 SQL is applied and passive sources are configured.
        section: 'CNII Watch', collapsible: true, icon: Shield, groupLabel: 'CNII Watch',
        items: [
            { id: 'cnii-overview', label: 'Overview', href: '/admin/cnii', domain: 'cnii', status: 'PARTIAL', roles: NOT_EXEC, icon: LayoutDashboard },
            { id: 'cnii-my-org', label: 'My organisation', href: '/admin/cnii/org/me', domain: 'cnii', status: 'PARTIAL', roles: ['executive'], icon: LayoutDashboard },
            { id: 'cnii-authorisations', label: 'CNII Scan Authorisations', href: '/admin/cnii/authorisations', domain: 'cnii', status: 'WORKING', roles: ['super_admin', 'soc_manager'], icon: ShieldCheck },
            ...CNII_SECTORS.map(([slug, label, icon]): NavItemConfig => (
                { id: `cnii-${slug}`, label, href: `/admin/cnii/${slug}`, domain: 'cnii', status: 'PARTIAL', roles: NOT_EXEC, icon }
            )),
        ],
    },
    {
        // Mobile App Suite and Intelli CODE (Mobile Application / Code Security) are v2 and not listed.
        section: 'Brand Protection', collapsible: true, icon: Shield, groupLabel: 'Brand Protection',
        items: [
            // roles: NOT_EXEC (not 'all') — F-01 containment restricted the backend to staff roles;
            // the client `executive` role would otherwise see a page that always 403s.
            { id: 'domain-intelligence', label: 'Domain Intelligence', href: '/admin/brand/domain', domain: 'brand', status: 'PARTIAL', roles: NOT_EXEC, icon: Globe },
            { id: 'social-suite', label: 'Social Suite', href: '/admin/brand/social', domain: 'brand', status: 'PARTIAL', roles: NOT_EXEC, icon: Users },
            { id: 'brand-suite', label: 'Brand Suite', href: '/admin/brand/brand', domain: 'brand', status: 'PARTIAL', roles: NOT_EXEC, icon: Shield },
            { id: 'executive-monitoring', label: 'Executive Monitoring', href: '/admin/brand/executive', domain: 'brand', status: 'PARTIAL', roles: NOT_EXEC, icon: UserCheck },
            // Had no nav entry at all (audit §4); the pages work for staff (/api/brand/apps,
            // /api/brand/signatures) and already carry the BrandIsolationNotice banner (Stage 0).
            { id: 'mobile-app-suite', label: 'Mobile App Suite', href: '/admin/brand/mobile', domain: 'brand', status: 'PARTIAL', roles: NOT_EXEC, icon: Smartphone },
            { id: 'intelli-code', label: 'Intelli CODE copyID', href: '/admin/brand/copyid', domain: 'brand', status: 'PARTIAL', roles: NOT_EXEC, icon: Code },
            { id: 'dark-web', label: 'Dark Web Monitor', href: '/admin/brand/darkweb', domain: 'brand', status: 'WORKING', roles: NOT_EXEC, icon: Eye },
        ],
    },
    {
        section: 'Infrastructure & Assets', collapsible: true, icon: Server, groupLabel: 'Infrastructure & Assets',
        items: [
            // Unified inventory (P14): Wazuh-managed and external assets, one record set (VMS Attack Surface).
            { id: 'infra-inventory', label: 'Asset Inventory', href: '/admin/vms/assets', domain: 'infra', status: 'WORKING', roles: VMS_READ, icon: Server },
            { id: 'digital-assets', label: 'Wazuh Endpoints', href: '/admin/vms/assets?category=wazuh', domain: 'infra', status: 'WORKING', roles: NOT_EXEC, icon: Monitor },
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
            { id: 'onboarding', label: 'Onboarding', href: '/admin/onboarding', domain: 'clients', status: 'WORKING', roles: MANAGER_ONLY, icon: ClipboardCheck },
        ],
    },
    {
        section: 'Settings', collapsible: true, icon: Settings, groupLabel: 'Settings',
        items: [
            { id: 'team', label: 'Team', href: '/admin/settings/team', domain: 'settings', status: 'WORKING', roles: SUPER_ADMIN, icon: Users },
            { id: 'org-access', label: 'Organisation Access', href: '/admin/settings/org-access', domain: 'settings', status: 'WORKING', roles: SUPER_ADMIN, icon: Building2 },
            { id: 'billing', label: 'Billing', href: '/admin/settings/billing', domain: 'settings', status: 'PARTIAL', roles: SUPER_ADMIN, icon: CreditCard },
            { id: 'analytics', label: 'Analytics', href: '/admin/settings/analytics', domain: 'settings', status: 'WORKING', roles: SUPER_ADMIN, icon: BarChart },
            { id: 'audit-log', label: 'Audit Log', href: '/admin/settings/audit', domain: 'settings', status: 'PARTIAL', roles: SUPER_ADMIN, icon: ScrollText },
            // Also carries the Stellar push ("Vendor Export Status") panel — ExportClients.tsx
            // already embeds <PushStatus /> (pre-existing, commit 284f06b); no separate nav entry.
            { id: 'export-clients', label: 'Export Clients', href: '/admin/settings/export-clients', domain: 'settings', status: 'WORKING', roles: SUPER_ADMIN, icon: KeyRound },
            { id: 'wazuh-groups', label: 'Wazuh Groups', href: '/admin/settings/wazuh-groups', domain: 'settings', status: 'WORKING', roles: SUPER_ADMIN, icon: Network },
            { id: 'platform-health', label: 'Platform Health', href: '/admin/settings/health', domain: 'settings', status: 'WORKING', roles: MANAGER_ONLY, icon: Activity },
        ],
    },
];

// Client portal. Sign-in itself runs on this backend (phase P21, routes/portal.ts) and works —
// this comment used to say sign-in depended on an unreachable external backend, which stopped
// being true at P21 and was corrected in the Release 2 Stage 6/client-auth pass. The per-item
// BROKEN labels below are a separate, real fact: those specific pages call non-client-scoped
// routes (/api/brand/*, /api/org-cti/*, etc.) that a signed-in portal_user session cannot reach
// (requireAuth confines it to /api/client/*) — toNavGroups() hides them (see Stage 6 above).
export const CLIENT_NAV: NavSectionConfig[] = [
    {
        section: '', collapsible: false,
        items: [
            { id: 'client-dashboard', label: 'Dashboard', href: '/client/dashboard', domain: 'overview', status: 'PARTIAL', roles: 'all', icon: LayoutDashboard },
        ],
    },
    {
        // Client VMS portal (P21): the client's own organisation, read from /api/client/vms.
        section: 'Vulnerability Management', collapsible: true, icon: Radar, groupLabel: 'Vulnerability Management',
        items: [
            { id: 'client-vms-overview', label: 'Overview', href: '/client/vms', domain: 'vms', status: 'WORKING', roles: 'all', icon: Radar },
            { id: 'client-vms-assets', label: 'Assets', href: '/client/vms/assets', domain: 'vms', status: 'WORKING', roles: 'all', icon: Server },
            { id: 'client-vms-findings', label: 'Vulnerabilities', href: '/client/vms/findings', domain: 'vms', status: 'WORKING', roles: 'all', icon: ShieldAlert },
            { id: 'client-vms-remediation', label: 'Remediation', href: '/client/vms/remediation', domain: 'vms', status: 'WORKING', roles: 'all', icon: ClipboardCheck },
            { id: 'client-vms-reports', label: 'Reports', href: '/client/vms/reports', domain: 'vms', status: 'WORKING', roles: 'all', icon: FileBarChart },
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
            { id: 'client-digital-assets', label: 'Digital Assets', href: '/client/infra/assets', domain: 'infra', status: 'PARTIAL', roles: 'all', icon: Server },
            { id: 'client-dns', label: 'DNS Suite', href: '/client/infra/dns', domain: 'infra', status: 'BROKEN', roles: 'all', icon: Network },
        ],
    },
    {
        section: 'SecOps & Response', collapsible: true, icon: Activity, groupLabel: 'SecOps & Response',
        items: [
            { id: 'client-threat-management', label: 'Security Alerts', href: '/client/secops/threats', domain: 'secops', status: 'PARTIAL', roles: 'all', icon: Activity },
            { id: 'client-cases', label: 'Cases', href: '/client/secops/cases', domain: 'secops', status: 'BROKEN', roles: 'all', icon: Siren },
            // SecurityReportCard's mode="client" branch calls /api/client/security-assessment,
            // which portal_user can reach — this one was mislabeled BROKEN; it genuinely works.
            { id: 'client-report-card', label: 'Security Report Card', href: '/client/secops/security-assessment', domain: 'secops', status: 'PARTIAL', roles: 'all', icon: Activity },
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

/** Converts config sections into the NavGroup shape Sidebar.tsx renders.
 * BROKEN/PLANNED items are hidden from everyone except super_admin (the audit's recommendation,
 * §4.5): the client portal has no super_admin tier, so every BROKEN client item simply disappears;
 * a super_admin still sees them, now carrying a badge, instead of a page that fails for anyone
 * who opens it. A section left with no items after this (e.g. "Account" when its one item was
 * BROKEN) is dropped rather than rendered as an empty, uselessly-clickable accordion header. */
export function toNavGroups(sections: NavSectionConfig[], role: string): NavGroup[] {
    const isSuperAdmin = role === 'super_admin';
    return sections
        .map(({ items, ...section }) => ({
            ...section,
            items: items
                .filter((item) => isSuperAdmin || (item.status !== 'BROKEN' && item.status !== 'PLANNED'))
                .map(({ label, href, icon, roles, match, status }): NavItem => ({
                    label, href, icon,
                    ...(roles === 'all' ? {} : { roles }),
                    ...(match?.length ? { match } : {}),
                    ...(isSuperAdmin && (status === 'BROKEN' || status === 'PLANNED') ? { badge: status } : {}),
                })),
        }))
        .filter((section) => section.items.length > 0);
}

/** Every href in both navs — used by scripts/check-nav-routes.mjs. */
export const ALL_NAV_HREFS: string[] = [...ADMIN_NAV, ...CLIENT_NAV].flatMap((s) => s.items.map((i) => i.href));
