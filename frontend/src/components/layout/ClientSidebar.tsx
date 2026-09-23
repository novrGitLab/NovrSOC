'use client';

import {
    LayoutDashboard, Globe, Users, Shield, UserCheck, Smartphone, Code,
    Crosshair, AlertTriangle, Link as LinkIcon, Monitor, Building, Server, Network, Cpu,
    Mail, MessageSquare, ShieldAlert, Activity, Siren, Bell,
    HardDrive, BarChart, CreditCard,
} from 'lucide-react';
import { Sidebar, type NavGroup } from './Sidebar';

const clientNav: NavGroup[] = [
    {
        section: '',
        collapsible: false,
        items: [{ label: 'Dashboard', href: '/client/dashboard', icon: LayoutDashboard }],
    },
    {
        section: 'Brand Protection',
        collapsible: true,
        icon: Shield,
        groupLabel: 'Brand Protection',
        items: [
            { label: 'Domain Suite', href: '/client/brand/domain', icon: Globe },
            { label: 'Social Suite', href: '/client/brand/social', icon: Users },
            { label: 'Brand Suite', href: '/client/brand/brand', icon: Shield },
            { label: 'Executive Monitor', href: '/client/brand/executive', icon: UserCheck },
            { label: 'Mobile App Suite', href: '/client/brand/mobile', icon: Smartphone },
            { label: 'Intelli CODE copyID', href: '/client/brand/copyid', icon: Code },
        ],
    },
    {
        section: 'Threat Intelligence',
        collapsible: true,
        icon: Crosshair,
        groupLabel: 'Threat Intelligence',
        items: [
            { label: 'CTI Platform', href: '/client/threat/cti', icon: Crosshair },
            { label: 'Threat Advisory', href: '/client/threat/advisory', icon: AlertTriangle },
            { label: 'URL Scan Suite', href: '/client/threat/urlscan', icon: LinkIcon },
            { label: 'Website Scanning', href: '/client/threat/webscan', icon: Monitor },
            { label: 'Vendor Assessments', href: '/client/threat/vendor', icon: Building },
        ],
    },
    {
        section: 'Infrastructure',
        collapsible: true,
        icon: Server,
        groupLabel: 'Infrastructure',
        items: [
            { label: 'Digital Assets', href: '/client/infra/assets', icon: Server },
            { label: 'DNS Suite', href: '/client/infra/dns', icon: Network },
            { label: 'WebLogic Appliances', href: '/client/infra/weblogic', icon: Cpu },
        ],
    },
    {
        section: 'Email Security',
        collapsible: true,
        icon: Mail,
        groupLabel: 'Email Security',
        items: [
            { label: 'DMARC SaaS', href: '/client/email/dmarc', icon: Mail },
            { label: 'Messaging Suite', href: '/client/email/messaging', icon: MessageSquare },
            { label: 'Intelli CODE PHISHID', href: '/client/email/phishid', icon: ShieldAlert },
        ],
    },
    {
        section: 'SecOps & Response',
        collapsible: true,
        icon: Activity,
        groupLabel: 'SecOps & Response',
        items: [
            { label: 'Threat Management', href: '/client/secops/threats', icon: Activity },
            { label: 'Cases', href: '/client/secops/cases', icon: Siren },
            { label: 'Alert Communication', href: '/client/secops/alerts', icon: Bell },
        ],
    },
    {
        section: 'Data Continuity',
        collapsible: true,
        icon: HardDrive,
        groupLabel: 'Data Continuity',
        items: [
            { label: 'Data Loss Recovery', href: '/client/data/recovery', icon: HardDrive },
            { label: 'Recovery Credit', href: '/client/data/sla', icon: BarChart },
        ],
    },
    {
        section: 'Account',
        collapsible: false,
        items: [
            { label: 'Billing & Subscription', href: '/client/billing', icon: CreditCard },
        ],
    },
];

interface ClientSidebarProps {
    user: { name: string; email: string; role: string };
    onLogout: () => void;
}

export function ClientSidebar({ user, onLogout }: ClientSidebarProps) {
    return <Sidebar navGroups={clientNav} user={user} onLogout={onLogout} />;
}
