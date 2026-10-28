// Per-collector authentication (phase P31, Collector V1). Deliberately NOT the single shared
// ALERT_INGEST_TOKEN pattern (routes/ingest.ts) — a fleet of client-site appliances needs its own
// revocable identity per collector, not one secret shared by everything that ever forwards logs.
//
// A collector's credential is `<collectorId>.<secret>`. The id selects the row directly (no
// table scan to find which collector a request claims to be); the secret is hashed with SHA-256
// and compared with timingSafeEqual, exactly like ALERT_INGEST_TOKEN — a timing side-channel on
// the comparison would otherwise let an attacker recover the secret one byte at a time. The
// secret itself is never stored, logged, or returned again after the enrollment response that
// first issues it.

import { randomBytes, createHash, timingSafeEqual } from 'crypto';

export interface IssuedCredential { token: string; token_hash: string; token_prefix: string }

/** A new collector identity's full credential — shown to the caller exactly once. */
export function issueCredential(collectorId: string): IssuedCredential {
    const secret = randomBytes(32).toString('hex');
    return { token: `${collectorId}.${secret}`, token_hash: hashSecret(secret), token_prefix: secret.slice(0, 8) };
}

export function hashSecret(secret: string): string {
    return createHash('sha256').update(secret).digest('hex');
}

/** Splits a presented `Authorization: Bearer <id>.<secret>` header. Null if malformed. */
export function parseCredential(authHeader: string | undefined): { collectorId: string; secret: string } | null {
    const m = /^Bearer\s+([0-9a-f-]{36})\.([0-9a-f]{64})$/i.exec((authHeader ?? '').trim());
    if (!m) return null;
    return { collectorId: m[1], secret: m[2] };
}

/** Constant-time comparison of a presented secret against the stored hash. */
export function secretMatches(secret: string, storedHash: string): boolean {
    const a = Buffer.from(hashSecret(secret), 'hex');
    const b = Buffer.from(storedHash, 'hex');
    return a.length === b.length && timingSafeEqual(a, b);
}
