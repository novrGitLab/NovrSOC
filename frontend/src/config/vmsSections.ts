// The eight VMS sections (redesign, phase P20) and their pages. The sidebar shows one item per
// section (config/nav.ts); app/admin/vms/layout.tsx shows the section's pages as tabs.
// managerOnly is presentation only: those pages read endpoints the backend restricts to vms:scope.
import {
    Radar, Boxes, Bug, Gauge as GaugeIcon, Wrench, Activity, FileBarChart, Cog, type LucideIcon,
} from 'lucide-react';

export interface VmsPage { href: string; label: string }
export interface VmsSection { id: string; label: string; href: string; icon: LucideIcon; managerOnly?: boolean; pages: VmsPage[] }

export const VMS_SECTIONS: VmsSection[] = [
    { id: 'overview', label: 'Overview', href: '/admin/vms', icon: Radar, pages: [{ href: '/admin/vms', label: 'VMS Dashboard' }] },
    {
        id: 'assets', label: 'Asset Management', href: '/admin/vms/assets', icon: Boxes,
        pages: [
            { href: '/admin/vms/assets', label: 'Asset Inventory' },
            { href: '/admin/vms/import', label: 'Asset Import' },
            { href: '/admin/vms/discovery', label: 'Asset Discovery' },
            { href: '/admin/vms/authorisation', label: 'Scan Authorisation' },
            { href: '/admin/vms/attack-surface', label: 'Attack Surface' },
            { href: '/admin/vms/services', label: 'Services & Technologies' },
        ],
    },
    {
        id: 'detection', label: 'Vulnerability Detection', href: '/admin/vms/findings', icon: Bug,
        pages: [
            { href: '/admin/vms/findings', label: 'Vulnerability Findings' },
            { href: '/admin/vms/scans', label: 'Scan Management' },
            { href: '/admin/vms/scans/history', label: 'Scan Results & History' },
        ],
    },
    {
        id: 'risk', label: 'Risk & Prioritization', href: '/admin/vms/risk', icon: GaugeIcon,
        pages: [
            { href: '/admin/vms/risk', label: 'Risk Overview' },
            { href: '/admin/vms/risk/exposure', label: 'Exposure & Threat Context' },
        ],
    },
    {
        id: 'remediation', label: 'Remediation & Verification', href: '/admin/vms/remediation', icon: Wrench,
        pages: [
            { href: '/admin/vms/remediation', label: 'Remediation Tasks' },
            { href: '/admin/vms/remediation/ai', label: 'AI Remediation Plans' },
            { href: '/admin/vms/remediation/verification', label: 'Verification & Rescans' },
        ],
    },
    {
        id: 'monitoring', label: 'Continuous Monitoring', href: '/admin/vms/monitoring', icon: Activity,
        pages: [
            { href: '/admin/vms/monitoring', label: 'Monitoring Rules' },
            { href: '/admin/vms/monitoring/schedules', label: 'Scan Schedules' },
            { href: '/admin/vms/monitoring/changes', label: 'Changes & Alerts' },
        ],
    },
    {
        id: 'reporting', label: 'Reporting & Audit', href: '/admin/vms/report', icon: FileBarChart,
        pages: [
            { href: '/admin/vms/report', label: 'Reports' },
            { href: '/admin/vms/audit', label: 'Audit Trail' },
        ],
    },
    {
        id: 'operations', label: 'Scanner Operations', href: '/admin/vms/operations', icon: Cog, managerOnly: true,
        pages: [
            { href: '/admin/vms/operations', label: 'Scanner Integrations' },
            { href: '/admin/vms/operations/workers', label: 'Worker Health' },
            { href: '/admin/vms/operations/config', label: 'Scan Policies & Configuration' },
        ],
    },
];

/** The section and page for a pathname: the longest matching page route wins. */
export function vmsLocate(pathname: string): { section: VmsSection; page: VmsPage } | null {
    let best: { section: VmsSection; page: VmsPage } | null = null;
    for (const section of VMS_SECTIONS) {
        for (const page of section.pages) {
            const hit = pathname === page.href || (page.href !== '/admin/vms' && pathname.startsWith(`${page.href}/`));
            if (hit && (!best || page.href.length > best.page.href.length)) best = { section, page };
        }
    }
    return best ?? (pathname.startsWith('/admin/vms') ? { section: VMS_SECTIONS[0], page: VMS_SECTIONS[0].pages[0] } : null);
}
