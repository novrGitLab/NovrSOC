'use client';

import { useState } from 'react';
import { Crosshair, ClipboardList, MessageSquare } from 'lucide-react';
import { ThreatHunting } from './ThreatHunting';
import { ShiftHandover } from './ShiftHandover';
import { TeamCommunication } from './TeamCommunication';

// Security Ops Management — Threat Hunting, Shift Handover and Team Communication as tabs.
// Threat Hunting is also reachable directly at /admin/secops/hunting. The Reports and Playbooks
// tabs were removed in the 2026-10 cleanup (PlaybookManagement.tsx is kept, unmounted, for
// re-homing playbook editing later).
const TABS = [
    { id: 'hunting', label: 'Threat Hunting', icon: Crosshair },
    { id: 'handover', label: 'Shift Handover', icon: ClipboardList },
    { id: 'broadcast', label: 'Team Communication', icon: MessageSquare },
] as const;
type TabId = (typeof TABS)[number]['id'];

export function SecOpsManagement() {
    const [activeTab, setActiveTab] = useState<TabId>('hunting');

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Security Ops Management</h1>
                <p className="text-xs text-foreground-muted">Threat hunting, shift handover, and team communication in one place.</p>
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

            {activeTab === 'hunting' && <ThreatHunting />}
            {activeTab === 'handover' && <ShiftHandover />}
            {activeTab === 'broadcast' && <TeamCommunication />}
        </div>
    );
}
