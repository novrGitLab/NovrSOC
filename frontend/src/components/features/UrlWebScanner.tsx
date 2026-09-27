'use client';

import { useState } from 'react';
import { Link as LinkIcon, Globe2 } from 'lucide-react';
import { UrlScanSuite } from './UrlScanSuite';
import { WebsiteScanning } from './WebsiteScanning';

// Combined URL and website scanner — the admin page at /admin/threat/urlscan. The website
// scanner is also reachable alone at /admin/threat/webscan, and the client portal uses both
// components directly. One home with a tab switch, since they're closely related (both are
// "check this thing for me" security scanners) but scan different targets (a single URL's
// reputation vs. a domain's overall security posture) and call different backend endpoints.
const TABS = [
    { id: 'url', label: 'URL Reputation Scanner', icon: LinkIcon },
    { id: 'website', label: 'Website Security Scanner', icon: Globe2 },
] as const;
type TabId = (typeof TABS)[number]['id'];

export function UrlWebScanner() {
    const [activeTab, setActiveTab] = useState<TabId>('url');

    return (
        <div className="space-y-4">
            <div className="flex gap-1 bg-card-muted rounded-lg p-1 w-fit">
                {TABS.map((tab) => {
                    const Icon = tab.icon;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold transition-colors ${
                                activeTab === tab.id ? 'bg-card text-blue shadow-sm' : 'text-foreground-muted hover:text-foreground'
                            }`}
                        >
                            <Icon size={13} />
                            {tab.label}
                        </button>
                    );
                })}
            </div>

            {activeTab === 'url' ? <UrlScanSuite /> : <WebsiteScanning />}
        </div>
    );
}
