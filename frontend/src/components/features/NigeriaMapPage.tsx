'use client';

import { useEffect, useState } from 'react';
import { Globe } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { NigeriaThreatMap, type FeedAdvisory } from '@/components/geo/NigeriaThreatMap';

// Full-page home for the Nigeria threat map — same NigeriaThreatMap widget the dashboard
// embeds at `lg:col-span-5` (a fixed-width grid column), just unconstrained here so it gets
// the room its own fullscreen/time-range/stat-card UI was actually designed for. The dashboard
// keeps its smaller, grid-constrained copy of the same widget; this page isn't a replacement
// for that one, just a dedicated place to look at it full-size.
export function NigeriaMapPage() {
    const [advisories, setAdvisories] = useState<FeedAdvisory[] | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/advisories'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json())
            .then((data) => setAdvisories(Array.isArray(data?.advisories) ? data.advisories : []))
            .catch(() => setAdvisories([]));
    }, []);

    return (
        <div className="space-y-4">
            <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-purple/10 flex items-center justify-center">
                    <Globe className="w-4 h-4 text-purple" />
                </div>
                <div>
                    <h1 className="text-lg font-black text-foreground">Nigeria Threat Map</h1>
                    <p className="text-xs text-foreground-muted">Nigerian Threat Advisory · State-by-state threat landscape across all 37 states and the FCT</p>
                </div>
            </div>

            <NigeriaThreatMap advisories={advisories} />
        </div>
    );
}
