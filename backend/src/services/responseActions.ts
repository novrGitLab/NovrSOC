// Analyst-run response actions for a case — the "Execute" button on a case's response tasks.
//
// These are the same actions the SOAR engine (infra/soar/soar.py) runs automatically, done from
// the backend for one case on demand. Each returns an honest outcome: 'success' only when the
// remote system accepted the action, 'skipped' when it isn't configured or doesn't apply (with
// the reason), 'failed' otherwise. soar_log and timeline wording matches the engine's, so the
// SOAR Automation page's derived flags (IP blocked, email sent, CISO notified) count manual runs
// the same way as automated ones.
import https from 'https';
import { URL } from 'url';
import { getSupabase } from './geoEnrichment';
import { enrichIOC } from './iocEnrichment';
import { runActiveResponse } from './wazuh';
import { sendEscalationEmail, isEmailEnabled, sendCaseNotificationEmail, socNotificationRecipients } from './email';
import { addTimeline, formatWAT, dbErrorMessage, type CaseRow } from './cases';

export const EXECUTABLE_STEPS = ['block_ip', 'isolate_agent', 'enrich_iocs', 'notify_email', 'notify_ciso'] as const;
export type ExecutableStep = (typeof EXECUTABLE_STEPS)[number];
export const isExecutableStep = (v: unknown): v is ExecutableStep => typeof v === 'string' && (EXECUTABLE_STEPS as readonly string[]).includes(v);

export interface ActionResult {
    outcome: 'success' | 'skipped' | 'failed';
    message: string;
    affected: number;
}

const ok = (message: string): ActionResult => ({ outcome: 'success', message, affected: 1 });
const skip = (message: string): ActionResult => ({ outcome: 'skipped', message, affected: 0 });
const fail = (message: string): ActionResult => ({ outcome: 'failed', message, affected: 0 });

// Private, loopback, link-local, CGNAT and reserved IPv4 ranges — never blocked or enriched.
function isPublicIPv4(ip: string): boolean {
    const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    const [a, b] = [Number(m[1]), Number(m[2])];
    if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) return false;
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    return true;
}

async function soarLog(c: CaseRow, action: string, result: string): Promise<void> {
    const supabase = getSupabase();
    if (!supabase) return;
    const { error } = await supabase.from('soar_log').insert({ case_id: c.id, tier: c.tier, action, result, automated: false });
    if (error) console.error('[responseActions] soar_log insert failed:', dbErrorMessage(error));
}

// OPNsense's API usually sits behind a self-signed certificate; verification is opt-in, as in
// the engine. Node's fetch can't relax TLS per request, hence https.request.
function opnsensePost(path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> | null }> {
    const base = new URL(process.env.OPNSENSE_URL as string);
    const payload = JSON.stringify(body);
    const auth = Buffer.from(`${process.env.OPNSENSE_KEY}:${process.env.OPNSENSE_SECRET}`).toString('base64');
    return new Promise((resolve, reject) => {
        const req = https.request({
            hostname: base.hostname,
            port: base.port || 443,
            path,
            method: 'POST',
            headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
            rejectUnauthorized: process.env.OPNSENSE_VERIFY_TLS === 'true',
            timeout: 10000,
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => (data += chunk));
            res.on('end', () => {
                try { resolve({ status: res.statusCode ?? 500, json: JSON.parse(data) }); } catch { resolve({ status: res.statusCode ?? 500, json: null }); }
            });
        });
        req.on('timeout', () => req.destroy(new Error('timed out after 10s')));
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

async function blockIp(c: CaseRow): Promise<ActionResult> {
    const ip = c.source_ip ?? '';
    if (!ip) return skip('No source IP on this case');
    if (!isPublicIPv4(ip)) return skip(`${ip} is not a public IPv4 address — nothing to block at the edge`);
    if (!process.env.OPNSENSE_URL || !process.env.OPNSENSE_KEY || !process.env.OPNSENSE_SECRET) {
        const r = skip('OPNsense not configured — set OPNSENSE_URL, OPNSENSE_KEY and OPNSENSE_SECRET on Railway');
        await soarLog(c, `Block IP ${ip}`, `SKIPPED — ${r.message}`);
        return r;
    }
    const alias = process.env.OPNSENSE_ALIAS || 'novrsoc_blocked';
    try {
        // alias_util/add updates the live pf table immediately. The alias must exist (Host(s))
        // and be referenced by a block rule. OPNsense answers 200 for both outcomes and puts
        // the verdict in `status`.
        const { status, json } = await opnsensePost(`/api/firewall/alias_util/add/${encodeURIComponent(alias)}`, { address: ip });
        if (status < 300 && String(json?.status ?? '').toLowerCase() === 'done') {
            await getSupabase()?.from('cases').update({ containment_done: true, updated_at: new Date().toISOString() }).eq('id', c.id);
            await soarLog(c, `Block IP ${ip}`, 'SUCCESS');
            await addTimeline(c.id, 'NovrSOC', `Source IP ${ip} blocked at OPNsense (alias ${alias})`, { automated: true });
            return ok(`IP ${ip} blocked at OPNsense (alias ${alias})`);
        }
        const r = fail(`OPNsense refused the block: HTTP ${status} ${JSON.stringify(json ?? {}).slice(0, 120)}`);
        await soarLog(c, `Block IP ${ip}`, `FAILED: ${r.message}`);
        return r;
    } catch (err) {
        const r = fail(`Could not reach OPNsense: ${err instanceof Error ? err.message : err}`);
        await soarLog(c, `Block IP ${ip}`, `ERROR: ${r.message}`);
        return r;
    }
}

async function isolateAgent(c: CaseRow): Promise<ActionResult> {
    const agentId = (c.agent_id ?? '').padStart(3, '0');
    if (!c.agent_id || agentId === '000') return skip('No endpoint agent on this case (000 is the manager itself)');
    const command = process.env.WAZUH_ISOLATE_COMMAND;
    if (!command) {
        // No default on purpose. Wazuh ships no host-isolation response, and the obvious
        // stand-in, firewall-drop, only blocks one source IP on the agent — reporting that as
        // "isolated" would tell an analyst an endpoint is cut off when it isn't.
        const r = skip('WAZUH_ISOLATE_COMMAND not set — deploy an isolation active response to agents and name it here');
        await soarLog(c, `Isolate agent ${agentId}`, `SKIPPED — ${r.message}`);
        return r;
    }
    try {
        const res = await runActiveResponse(agentId, command, c.source_ip ?? undefined);
        if (res.accepted) {
            await getSupabase()?.from('cases').update({ containment_done: true, updated_at: new Date().toISOString() }).eq('id', c.id);
            await soarLog(c, `Isolate agent ${agentId}`, 'REQUESTED — accepted by Wazuh manager');
            await addTimeline(c.id, 'NovrSOC', `Isolation (${command}) sent to agent ${agentId} via Wazuh active response`, { automated: true });
            return ok(`Isolation requested for ${c.agent_name ?? agentId} — accepted by the Wazuh manager (check the agent's active-responses.log to confirm it ran)`);
        }
        const r = fail(`Wazuh did not accept the command: ${res.detail}`);
        await soarLog(c, `Isolate agent ${agentId}`, `FAILED: ${res.detail}`);
        return r;
    } catch (err) {
        const r = fail(`Wazuh API error: ${err instanceof Error ? err.message : err}`);
        await soarLog(c, `Isolate agent ${agentId}`, `ERROR: ${r.message}`);
        return r;
    }
}

async function enrichIocs(c: CaseRow): Promise<ActionResult> {
    const ip = c.source_ip ?? '';
    if (!ip) return skip('No source IP to enrich');
    if (!isPublicIPv4(ip)) return skip(`${ip} is a private/internal address — threat feeds have nothing on it`);
    const supabase = getSupabase();
    if (!supabase) return fail('Case store not configured');
    try {
        // Called directly rather than through /api/public/scan, which is capped at 10/hour/IP.
        const result = await enrichIOC(ip, 'ip');
        const row = { verdict: result.verdict, risk_score: result.risk_score, enriched_at: new Date().toISOString() };
        // case_iocs has no unique (case_id, value) constraint, so an upsert on it would error;
        // update the existing row if there is one, insert otherwise.
        const { data: existing } = await supabase.from('case_iocs').select('id').eq('case_id', c.id).eq('value', ip).limit(1);
        const { error } = existing && existing.length > 0
            ? await supabase.from('case_iocs').update(row).eq('id', existing[0].id)
            : await supabase.from('case_iocs').insert({ case_id: c.id, type: 'ip', value: ip, ...row });
        if (error) return fail(`Enriched, but could not save the IOC: ${dbErrorMessage(error)}`);
        await soarLog(c, `Enrich IOC ${ip}`, `SUCCESS: ${result.verdict} (${result.risk_score})`);
        await addTimeline(c.id, 'NovrSOC', `IOC enriched: ${ip} — verdict ${result.verdict}, score ${result.risk_score}`, { automated: true });
        return ok(`${ip} enriched — verdict ${result.verdict}, score ${result.risk_score}`);
    } catch (err) {
        return fail(`Enrichment failed: ${err instanceof Error ? err.message : err}`);
    }
}

// Team notification by email. Goes to the SOC mailbox
// (ALERT_EMAIL_TO, else CISO_EMAIL, else soc@cybernovr.com).
async function notifyEmail(c: CaseRow, by: string): Promise<ActionResult> {
    const to = socNotificationRecipients();
    if (!isEmailEnabled()) {
        const r = skip('Email is disabled — set EMAIL_ENABLED=true and RESEND_API_KEY on Railway');
        await soarLog(c, 'Email notification', `SKIPPED — ${r.message}`);
        return r;
    }
    try {
        await sendCaseNotificationEmail({
            to, case_number: c.case_number, title: c.title, severity: c.severity,
            headline: `Case update from ${by}`, agent: c.agent_name, source_ip: c.source_ip, detail: c.description,
        });
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await soarLog(c, 'Email notification', `FAILED: ${msg}`);
        return fail(`Email failed: ${msg}`);
    }
    await soarLog(c, 'Email notification', 'SUCCESS');
    await addTimeline(c.id, 'NovrSOC', `Email notification sent to ${to.join(', ')}`, { automated: true });
    return ok(`Email notification sent to ${to.join(', ')}`);
}

async function notifyCiso(c: CaseRow, by: string): Promise<ActionResult> {
    const to = process.env.CISO_EMAIL || 'soc@cybernovr.com';
    if (!isEmailEnabled()) {
        const r = skip('Email is disabled — set EMAIL_ENABLED=true and RESEND_API_KEY on Railway');
        await soarLog(c, 'CISO email', `SKIPPED — ${r.message}`);
        return r;
    }
    try {
        await sendEscalationEmail({
            to: [to], incident_number: c.case_number, title: c.title, severity: c.severity,
            assignee: c.assigned_to ?? 'Unassigned', opened_at: formatWAT(c.created_at), escalated_by: by,
            note: 'Sent from a case response task.',
        });
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await soarLog(c, 'CISO email', `FAILED: ${msg}`);
        return fail(`Email failed: ${msg}`);
    }
    await getSupabase()?.from('cases').update({ escalated: true, updated_at: new Date().toISOString() }).eq('id', c.id);
    await soarLog(c, 'CISO email', 'SUCCESS');
    await addTimeline(c.id, 'NovrSOC', `CISO escalation email sent to ${to}`, { automated: true });
    return ok(`CISO email sent to ${to}`);
}

export async function executeStep(step: ExecutableStep, c: CaseRow, by: string): Promise<ActionResult> {
    switch (step) {
        case 'block_ip': return blockIp(c);
        case 'isolate_agent': return isolateAgent(c);
        case 'enrich_iocs': return enrichIocs(c);
        case 'notify_email': return notifyEmail(c, by);
        case 'notify_ciso': return notifyCiso(c, by);
    }
}
