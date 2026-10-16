// VMS Release 2 background work (phase P5), where mutating jobs run (lib/runtimeEnv.ts):
//   • every hour: Wazuh endpoints and vulnerabilities into VMS (services/wazuhVulnSync.ts)
//   • every 6 hours: CVE intelligence from CISA KEV, FIRST EPSS, NVD and OSV (services/cveIntel.ts),
//     then risk and priority recomputed for every finding (lib/riskScore.ts)
// Each run's outcome is logged; a failed source is reported and retried on the next run.

import { refreshCveIntel } from '../services/cveIntel';
import { recomputeRisk } from '../services/vmsFindings';
import { syncWazuhVulnerabilities } from '../services/wazuhVulnSync';

export const lastVmsIntelRun: { intel: Record<string, unknown> | null; wazuh: Record<string, unknown>[] | null; at: string | null } = { intel: null, wazuh: null, at: null };

export function startVmsIntelJob(): void {
    if (process.env.VMS_INTEL_ENABLED === 'false') { console.log('[vms-intel] disabled by VMS_INTEL_ENABLED=false'); return; }
    let intelRunning = false;
    let wazuhRunning = false;
    const intel = async () => {
        if (intelRunning) return;
        intelRunning = true;
        try {
            const r = await refreshCveIntel();
            const changed = await recomputeRisk({});
            lastVmsIntelRun.intel = { ...r, risk_changed: changed };
            lastVmsIntelRun.at = new Date().toISOString();
            console.log(`[vms-intel] ${r.tracked} CVEs: KEV ${r.kev_marked}, EPSS ${r.epss_updated}, NVD ${r.nvd_updated}, OSV ${r.osv ? `${r.osv.state} (${r.osv.found} found, ${r.osv.not_found} none)` : 'not run'}; risk changed on ${changed} finding(s)${r.errors.length ? `; errors: ${r.errors.slice(0, 3).join(' | ')}` : ''}${r.osv?.errors.length ? `; OSV: ${r.osv.errors.slice(0, 2).join(' | ')}` : ''}`);
        } catch (err) {
            console.error('[vms-intel] failed:', err instanceof Error ? err.message : err);
        } finally { intelRunning = false; }
    };
    const wazuh = async () => {
        if (wazuhRunning) return;
        wazuhRunning = true;
        try {
            const r = await syncWazuhVulnerabilities();
            lastVmsIntelRun.wazuh = r as unknown as Record<string, unknown>[];
            for (const x of r) console.log(`[vms-wazuh] ${x.org}: ${x.agents} agents, ${x.vulnerabilities} vulnerabilities, ${x.new_findings} new, ${x.verified} verified${x.complete ? '' : ' (incomplete — absence not evaluated)'}${x.errors.length ? `; ${x.errors[0]}` : ''}`);
        } catch (err) {
            console.error('[vms-wazuh] failed:', err instanceof Error ? err.message : err);
        } finally { wazuhRunning = false; }
    };
    setTimeout(() => { void wazuh(); void intel(); }, 60_000).unref();
    setInterval(() => { void wazuh(); }, 60 * 60_000).unref();
    setInterval(() => { void intel(); }, 6 * 60 * 60_000).unref();
}
