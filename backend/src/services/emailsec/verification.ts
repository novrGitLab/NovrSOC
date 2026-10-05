// Domain ownership verification for Email Security.
//
// An organisation proves it controls a domain by publishing a TXT record NovrSOC gives it:
//     _novrsoc-verification.<domain>  TXT  "novrsoc-verification=<token>"
// The token is an HMAC of (org_id, domain) with a server secret, so it is stable, different for
// every tenant, cannot be guessed by another tenant, and needs no extra database column. The
// result of each check is stored with the DNS inspection history (email_dns_checks.result), so
// "verified" always reflects the most recent real lookup. NovrSOC never edits DNS.
import { createHmac } from 'crypto';
import { dnsClient } from './dnsInspect';
import { appEnvironment } from '../../lib/runtimeEnv';

export type VerificationState = 'verified' | 'not_found' | 'incorrect_value' | 'dns_error' | 'unavailable';
export interface VerificationRecord { type: 'TXT'; host: string; name: string; value: string }
export interface VerificationResult { state: VerificationState; checked_at: string; detail: string; found: string[] }

// The verification secret. Production and staging (deployed environments) require a DEDICATED
// EMAILSEC_VERIFICATION_SECRET: at least 32 characters and not equal to JWT_SECRET, so leaking or
// rotating one secret never affects the other. Without it verification is unavailable — it fails
// closed (no domain can become verified) and the backend says so at startup; it does not crash the
// rest of the platform. Development and test may fall back to JWT_SECRET.
export const MIN_VERIFICATION_SECRET_LENGTH = 32;
export function verificationSecretPolicy(env: NodeJS.ProcessEnv = process.env): { secret: string | null; source: 'dedicated' | 'jwt_fallback' | 'none'; reason: string } {
    const app = appEnvironment(env).env;
    const dedicated = (env.EMAILSEC_VERIFICATION_SECRET ?? '').trim();
    const deployed = app === 'production' || app === 'staging';
    if (dedicated) {
        if (deployed && dedicated.length < MIN_VERIFICATION_SECRET_LENGTH) return { secret: null, source: 'none', reason: `EMAILSEC_VERIFICATION_SECRET is shorter than ${MIN_VERIFICATION_SECRET_LENGTH} characters` };
        if (deployed && dedicated === (env.JWT_SECRET ?? '').trim()) return { secret: null, source: 'none', reason: 'EMAILSEC_VERIFICATION_SECRET must not be the same value as JWT_SECRET' };
        return { secret: dedicated, source: 'dedicated', reason: 'EMAILSEC_VERIFICATION_SECRET is set' };
    }
    if (deployed) return { secret: null, source: 'none', reason: `EMAILSEC_VERIFICATION_SECRET is required in ${app} (no JWT_SECRET fallback)` };
    const jwt = (env.JWT_SECRET ?? '').trim();
    return jwt ? { secret: jwt, source: 'jwt_fallback', reason: `${app}: using JWT_SECRET because EMAILSEC_VERIFICATION_SECRET is not set` } : { secret: null, source: 'none', reason: 'no verification secret configured' };
}
const secret = () => verificationSecretPolicy().secret ?? '';

/** Startup line: never prints the secret, only whether a usable one is configured. */
export function announceVerificationSecret(): void {
    const p = verificationSecretPolicy();
    if (p.source === 'dedicated') return;
    if (p.source === 'jwt_fallback') { console.log(`[emailsec] Domain verification: ${p.reason}.`); return; }
    console.warn(`[emailsec] WARNING: domain verification is UNAVAILABLE — ${p.reason}. No domain can be verified, so Mailgun DMARC reports are not delivered until it is set.`);
}

/** The record this organisation must publish for this domain, or null if no secret is configured. */
export function verificationRecord(orgId: string, domain: string): VerificationRecord | null {
    const key = secret();
    if (!key) return null;
    const token = createHmac('sha256', key).update(`novrsoc-domain-verification:${orgId}:${domain.toLowerCase()}`).digest('hex').slice(0, 32);
    return { type: 'TXT', host: '_novrsoc-verification', name: `_novrsoc-verification.${domain}`, value: `novrsoc-verification=${token}` };
}

export async function checkVerification(orgId: string, domain: string): Promise<VerificationResult> {
    const checked_at = new Date().toISOString();
    const rec = verificationRecord(orgId, domain);
    if (!rec) return { state: 'unavailable', checked_at, detail: 'Domain verification is not configured on this NovrSOC deployment (EMAILSEC_VERIFICATION_SECRET).', found: [] };
    let txt: string[];
    try {
        txt = await dnsClient().txt(rec.name);
    } catch (err) {
        return { state: 'dns_error', checked_at, detail: `DNS lookup for ${rec.name} failed: ${(err as Error).message}`, found: [] };
    }
    const found = txt.filter((t) => t.trim().toLowerCase().startsWith('novrsoc-verification='));
    if (found.some((t) => t.trim() === rec.value)) return { state: 'verified', checked_at, detail: `${rec.name} has the expected record.`, found };
    if (found.length) return { state: 'incorrect_value', checked_at, detail: `${rec.name} has a NovrSOC verification record, but not the one for this organisation.`, found };
    return { state: 'not_found', checked_at, detail: `No TXT record found at ${rec.name} yet. DNS changes can take minutes to hours to appear.`, found: [] };
}
