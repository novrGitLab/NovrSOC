'use client';

import { useState } from 'react';
import { FileText, Crosshair, ClipboardList, MessageSquare, BookOpen } from 'lucide-react';
import { ReportsCenter } from './ReportsCenter';
import { ThreatHunting } from './ThreatHunting';
import { ShiftHandover } from './ShiftHandover';
import { TeamCommunication } from './TeamCommunication';
import { PlaybookManagement } from './PlaybookManagement';

// Security Ops Management — a single page hosting previously-separate sidebar entries as tabs
// (Reports Center, Threat Hunting, Shift Handover) plus Team Communication and Playbooks
// (CISO/soc_manager playbook CRUD — PlaybookManagement.tsx self-gates by role internally, so
// the tab itself stays visible to everyone the way this whole page already is). Each tab's
// component is unchanged from its own standalone page where one exists (still reachable
// directly at /admin/secops/reports, /hunting, /handover) — this is purely a second, tabbed
// home for them, same pattern as UrlWebScanner.tsx elsewhere in this app.
const TABS = [
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'hunting', label: 'Threat Hunting', icon: Crosshair },
    { id: 'handover', label: 'Shift Handover', icon: ClipboardList },
    { id: 'broadcast', label: 'Team Communication', icon: MessageSquare },
    { id: 'playbooks', label: 'Playbooks', icon: BookOpen },
] as const;
type TabId = (typeof TABS)[number]['id'];

export function SecOpsManagement() {
    const [activeTab, setActiveTab] = useState<TabId>('reports');

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Security Ops Management</h1>
                <p className="text-xs text-foreground-muted">Reports, threat hunting, shift handover, and team communication in one place.</p>
            </div>

            <div className="flex gap-1 bg-card-muted rounded-lg p-1 w-fit overflow-x-auto">
                {TABS.map((tab) => {
                    const Icon = tab.icon;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold whitespace-nowrap transition-colors ${
                                activeTab === tab.id ? 'bg-card text-blue shadow-sm' : 'text-foreground-muted hover:text-foreground'
                            }`}
                        >
                            <Icon size={13} />
                            {tab.label}
                        </button>
                    );
                })}
            </div>

            {activeTab === 'reports' && <ReportsCenter />}
            {activeTab === 'hunting' && <ThreatHunting />}
            {activeTab === 'handover' && <ShiftHandover />}
            {activeTab === 'broadcast' && <TeamCommunication />}
            {activeTab === 'playbooks' && <PlaybookManagement />}
        </div>
    );
}
