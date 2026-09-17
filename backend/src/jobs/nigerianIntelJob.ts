// Hourly Nigerian threat-intelligence collection. Mirrors the existing job pattern in this
// folder (autoClose.ts / incidentEscalation.ts): a tick function, an immediate first run, and an
// unref()'d interval so this never keeps the process alive on its own.
import { runNigerianIntelCollector, setLastCollectorResult } from '../services/nigerianIntelCollector';
import { seedNigerianDemoData, isDemoSeedEnabled } from '../services/nigeriaDemoSeed';
import { collectNITDAAdvisories } from '../services/nitdaFeed';

const CHECK_INTERVAL_MS = 60 * 60 * 1000; // hourly

async function tick(): Promise<void> {
    try {
        const result = await runNigerianIntelCollector();
        setLastCollectorResult(result);
    } catch (err) {
        console.error('[NigerianIntel] Job tick failed:', err);
    }

    // NITDA runs in its own try/catch, after the main collector rather than inside it: it is a
    // search-driven source (services/nitdaFeed.ts) and a Serper outage or exhausted quota must
    // not take down ngCERT/NCC/CBN collection, which does not depend on it.
    try {
        const nitda = await collectNITDAAdvisories();
        if (nitda.found > 0 || nitda.stored > 0) {
            console.log(`[NigerianIntel] NITDA: ${nitda.found} advisories found, ${nitda.stored} stored`);
        }
    } catch (err) {
        console.error('[NigerianIntel] NITDA collection failed:', err instanceof Error ? err.message : err);
    }
}

export function startNigerianIntelJob(): void {
    console.log('[NigerianIntel] Job started — checking every 60 minutes');

    // Demo baseline runs once at boot, BEFORE the collector, and only when SEED_DEMO_DATA=true.
    // It no-ops if any state already has a live attack count or any advisory already exists, so
    // it can never overwrite real collected intelligence — see services/nigeriaDemoSeed.ts.
    if (isDemoSeedEnabled()) {
        setTimeout(() => {
            void seedNigerianDemoData().catch((err) => console.error('[NigerianIntel] Demo seed failed:', err));
        }, 5_000).unref();
    }

    // Delayed rather than immediate: this run makes external HTTP calls to four hosts and can
    // take tens of seconds, and doing that synchronously with boot slows the first /health
    // response Railway waits on during a deploy.
    setTimeout(() => { void tick(); }, 15_000).unref();
    setInterval(() => { void tick(); }, CHECK_INTERVAL_MS).unref();
}
