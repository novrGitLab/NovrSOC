'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { FileText, Zap, Settings, User, Bell, Users, CreditCard, ChevronRight } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { getPortalUser } from '@/lib/portal-auth';
import { exportDataAsPDF } from '@/lib/exportPDF';

interface RightRailProps {
    portal: 'admin' | 'client';
}

interface AccountSummary {
    organisation: string;
    plan: string;
    role: string;
}

function useAccountSummary(portal: 'admin' | 'client'): AccountSummary {
    const [summary, setSummary] = useState<AccountSummary>({ organisation: 'Cybernovr', plan: 'Enterprise', role: '—' });

    useEffect(() => {
        if (portal === 'admin') {
            const u = getAdminUser();
            setSummary({ organisation: u.company, plan: 'Enterprise', role: u.role });
        } else {
            const u = getPortalUser();
            if (u) setSummary({ organisation: u.orgName, plan: u.orgPlan ?? 'Enterprise', role: u.portalRole });
        }
    }, [portal]);

    return summary;
}

function useAgentCount(): number | null {
    const [count, setCount] = useState<number | null>(null);
    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/status'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => { if (typeof d?.agent_count === 'number') setCount(d.agent_count); })
            .catch(() => {});
    }, []);
    return count;
}

function AccountOverviewCard({ portal }: { portal: 'admin' | 'client' }) {
    const summary = useAccountSummary(portal);
    const agentCount = useAgentCount();

    const rows = [
        { label: 'Organisation', value: summary.organisation },
        { label: 'Plan', value: summary.plan, valueClass: 'text-purple font-bold' },
        { label: 'Agents Active', value: agentCount !== null ? String(agentCount) : '—' },
        { label: 'Role', value: summary.role },
    ];

    return (
        <div className="bg-white border border-grey-100 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
                <h3 className="font-heading font-semibold text-sm text-grey-800">Account Overview</h3>
                <FileText size={16} className="text-grey-500" />
            </div>
            <div className="space-y-3">
                {rows.map((row) => (
                    <div key={row.label} className="flex justify-between text-sm">
                        <span className="text-grey-500">{row.label}</span>
                        <span className={`font-medium text-grey-800 ${row.valueClass ?? ''}`}>{row.value}</span>
                    </div>
                ))}
            </div>
            {/* Admin has no account page since the general settings page was removed (2026-10 cleanup). */}
            {portal === 'client' && (
                <a href="/client/settings" className="block mt-4 text-xs text-purple hover:underline transition-colors">
                    View Full Account →
                </a>
            )}
        </div>
    );
}

function SettingsCard({ portal, base }: { portal: 'admin' | 'client'; base: string }) {
    // Admin: only pages that exist. The general /admin/settings page (Profile, Notifications,
    // API Keys anchors) and Settings > Organisations were removed in the 2026-10 cleanup.
    // Client: Profile/Notifications deep-link into /client/settings (a placeholder page).
    const adminItems = [
        { label: 'Team Members', href: `${base}/settings/team`, icon: Users },
        { label: 'Billing', href: `${base}/settings/billing`, icon: CreditCard },
    ];
    const clientItems = [
        { label: 'Profile', href: `${base}/settings#profile`, icon: User },
        { label: 'Notifications', href: `${base}/settings#notifications`, icon: Bell },
        { label: 'Billing', href: `${base}/billing`, icon: CreditCard },
    ];
    const items = portal === 'admin' ? adminItems : clientItems;
    const router = useRouter();

    return (
        <div className="bg-white border border-grey-100 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
                <h3 className="font-heading font-semibold text-sm text-grey-800">Settings</h3>
                <Settings size={16} className="text-grey-500" />
            </div>
            <div className="space-y-2">
                {items.map((item) => {
                    const Icon = item.icon;
                    return (
                        <button
                            key={item.label}
                            onClick={() => router.push(item.href)}
                            className="w-full flex items-center justify-between px-3 py-2.5 rounded-lg hover:bg-[#F5F0FF] group transition-colors"
                        >
                            <div className="flex items-center gap-2.5">
                                <Icon size={14} className="text-grey-500 group-hover:text-purple transition-colors" />
                                <span className="text-sm text-grey-800 group-hover:text-purple transition-colors">{item.label}</span>
                            </div>
                            <ChevronRight size={12} className="text-grey-300 group-hover:text-purple transition-colors" />
                        </button>
                    );
                })}
            </div>
        </div>
    );
}

function QuickActionsCard({ portal, base }: { portal: 'admin' | 'client'; base: string }) {
    const router = useRouter();
    const summary = useAccountSummary(portal);

    const handleExportReport = () => {
        exportDataAsPDF('Account Summary', 'account-summary', [
            {
                heading: 'Account',
                rows: [
                    { label: 'Organisation', value: summary.organisation },
                    { label: 'Plan', value: summary.plan },
                    { label: 'Role', value: summary.role },
                    { label: 'Generated', value: new Date().toLocaleString() },
                ],
            },
        ]);
    };

    const adminActions = [
        { label: '⚡ Run Security Scan', action: () => router.push(`${base}/threat/cti`), color: 'text-orange' },
        { label: '📋 Export Report', action: handleExportReport, color: 'text-blue' },
    ];
    const clientActions = [
        { label: '⚡ Run Security Scan', action: () => router.push(`${base}/threat/cti`), color: 'text-orange' },
        { label: '📋 Export Report', action: handleExportReport, color: 'text-blue' },
        { label: 'View System Status', action: () => router.push('/status'), color: 'text-purple' },
    ];
    const actions = portal === 'admin' ? adminActions : clientActions;

    return (
        <div className="bg-white border border-grey-100 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
                <h3 className="font-heading font-semibold text-sm text-grey-800">Quick Actions</h3>
                <Zap size={16} className="text-orange" />
            </div>
            <p className="text-xs text-grey-500 mb-4">Frequently used administrative tasks.</p>
            <div className="space-y-1">
                {actions.map((action) => (
                    <button
                        key={action.label}
                        onClick={action.action}
                        className={`w-full text-left text-sm font-medium py-2 px-3 rounded-lg hover:bg-[#F5F0FF] transition-colors ${action.color}`}
                    >
                        {action.label}
                    </button>
                ))}
            </div>

        </div>
    );
}

export function RightRail({ portal }: RightRailProps) {
    const base = portal === 'admin' ? '/admin' : '/client';
    return (
        <div className="space-y-4">
            <AccountOverviewCard portal={portal} />
            <SettingsCard portal={portal} base={base} />
            <QuickActionsCard portal={portal} base={base} />
        </div>
    );
}
