'use client';

import { Info } from 'lucide-react';

// Genuinely not connected — despite the nav spec's "existing (OPNsense)" label, no OPNsense
// integration (route, service, or even a host/credential in .env) exists anywhere in this
// codebase. This page explains what the capability is and what it needs, rather than either
// hiding the nav entry or fabricating device data with nothing behind it.

const CAPABILITIES = [
    { icon: '📱', title: 'Unauthorised devices', desc: 'Unregistered endpoints appearing on the network, by MAC and first-seen time.' },
    { icon: '☁️', title: 'Shadow cloud', desc: 'Unsanctioned SaaS and cloud services in use, inferred from egress traffic.' },
    { icon: '🔌', title: 'Rogue access points', desc: 'Unauthorised WiFi access points and personal hotspots bridging the network.' },
];

export function ShadowIT() {
    return (
        <div className="space-y-5">
            <div>
                <h1 className="text-lg font-black text-foreground">Shadow IT Discovery</h1>
                <p className="text-xs text-foreground-muted">
                    Infrastructure · Unsanctioned devices, applications and services on your network
                </p>
            </div>

            <div className="bg-card border border-border rounded-xl p-6">
                <p className="text-sm text-foreground-muted max-w-2xl">
                    Shadow IT discovery finds the things nobody told you about — devices that joined the network without
                    being enrolled, cloud services staff signed up for on a company card, and access points plugged in
                    under a desk. It works by analysing traffic at the network perimeter, which means it needs a
                    firewall it can read from.
                </p>
            </div>

            <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3">
                <Info size={16} className="text-amber-700 shrink-0 mt-0.5" />
                <div>
                    <p className="text-sm text-amber-800 font-medium">Setup required — no data source connected</p>
                    <p className="text-xs text-amber-700 mt-1">
                        This page has no live data because no OPNsense firewall is deployed or reachable from this
                        backend yet. There is nothing to show, and nothing is being hidden. Once OPNsense is installed
                        at the network perimeter and its API is configured, discovered devices and services will appear
                        here automatically. Contact your NovrSOC administrator to schedule deployment.
                    </p>
                </div>
            </div>

            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">
                    What this will show once connected
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {CAPABILITIES.map((c) => (
                        <div key={c.title} className="bg-card border border-border rounded-xl p-4">
                            <div className="text-2xl mb-2">{c.icon}</div>
                            <p className="text-xs font-bold text-foreground mb-1">{c.title}</p>
                            <p className="text-[10px] text-foreground-muted">{c.desc}</p>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
