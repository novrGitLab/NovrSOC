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

export type VerificationState = 'verified' | 'not_found' | 'incorrect_value' | 'dns_error' | 'unavailable';
export interface VerificationRecord { type: 'TXT'; host: string; name: string; value: string }
export interface VerificationResult { state: VerificationState; checked_at: string; detail: string; found: string[] }

const secret = () => process.env.EMAILSEC_VERIFICATION_SECRET || process.env.JWT_SECRET || '';

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
