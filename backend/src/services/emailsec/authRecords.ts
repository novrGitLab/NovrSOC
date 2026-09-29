// SPF, DKIM and DMARC record parsing and validation. Pure functions — DNS lookups happen in
// dnsInspect.ts; everything here works on the record text, so it is fully unit-tested.
//
// Each parser returns the parsed record plus three lists written for the UI: errors (the
// record is broken or ineffective), warnings (it works but is weak) and recommendations (what
// to change). Nothing here guesses: a record that isn't published is `exists: false`, never
// "failing".
import { createPublicKey } from 'crypto';

export interface Findings { errors: string[]; warnings: string[]; recommendations: string[] }
const findings = (): Findings => ({ errors: [], warnings: [], recommendations: [] });

// ── SPF (RFC 7208) ────────────────────────────────────────────────────────────────────────

export type SpfQualifier = '+' | '-' | '~' | '?';
export interface SpfTerm { qualifier: SpfQualifier; mechanism: string; value: string | null }
export interface SpfRecord extends Findings {
    exists: boolean;
    raw: string | null;
    terms: SpfTerm[];
    modifiers: Record<string, string>;
    all: SpfQualifier | null;
    /** DNS-querying terms in this record alone (include, a, mx, ptr, exists, redirect). */
    lookups: number;
    includes: string[];
}

const SPF_MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const LOOKUP_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
const IPV4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/;

function validIp4(v: string): boolean {
    const m = IPV4_CIDR.exec(v);
    if (!m) return false;
    if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) return false;
    return m[6] === undefined || Number(m[6]) <= 32;
}
function validIp6(v: string): boolean {
    const [addr, cidr] = v.split('/');
    if (cidr !== undefined && !(/^\d{1,3}$/.test(cidr) && Number(cidr) <= 128)) return false;
    return /^[0-9a-f:.]+$/i.test(addr) && addr.includes(':');
}

/** Parse the SPF record from a domain's TXT records (each already joined from its chunks). */
export function parseSpf(txtRecords: string[]): SpfRecord {
    const spf = txtRecords.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    const out: SpfRecord = { exists: spf.length > 0, raw: spf[0] ?? null, terms: [], modifiers: {}, all: null, lookups: 0, includes: [], ...findings() };
    if (spf.length === 0) {
        out.errors.push('No SPF record is published.');
        out.recommendations.push('Publish a TXT record starting "v=spf1" that lists every service allowed to send for this domain, ending in "~all" or "-all".');
        return out;
    }
    if (spf.length > 1) out.errors.push(`${spf.length} SPF records are published. More than one is a permanent error (RFC 7208 §4.5) and receivers ignore SPF entirely.`);

    const parts = spf[0].trim().split(/\s+/).slice(1);
    for (const part of parts) {
        const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(part);
        if (mod) {
            const key = mod[1].toLowerCase();
            if (key === 'redirect' || key === 'exp') {
                if (out.modifiers[key]) out.errors.push(`The "${key}" modifier appears more than once.`);
                out.modifiers[key] = mod[2];
                if (key === 'redirect') out.lookups++;
            } else {
                out.warnings.push(`Unknown modifier "${key}" is ignored by receivers.`);
            }
            continue;
        }
        const m = /^([+\-~?]?)([a-z0-9]+)(?:[:/](.*))?$/i.exec(part);
        if (!m || !SPF_MECHANISMS.has(m[2].toLowerCase())) {
            out.errors.push(`"${part}" is not a valid SPF mechanism.`);
            continue;
        }
        const mechanism = m[2].toLowerCase();
        const qualifier = (m[1] || '+') as SpfQualifier;
        // ip4/ip6/include/exists take ":value"; a/mx may take ":domain" and/or "/cidr".
        const value = part.includes(':') ? part.slice(part.indexOf(':') + 1) : part.includes('/') ? part.slice(part.indexOf('/')) : null;
        out.terms.push({ qualifier, mechanism, value });
        if (LOOKUP_MECHANISMS.has(mechanism)) out.lookups++;
        if (mechanism === 'include') {
            if (!value) out.errors.push('"include" needs a domain, e.g. include:_spf.google.com.');
            else out.includes.push(value.toLowerCase());
        }
        if (mechanism === 'ip4' && (!value || !validIp4(value))) out.errors.push(`"${part}" is not a valid IPv4 address or range.`);
        if (mechanism === 'ip6' && (!value || !validIp6(value))) out.errors.push(`"${part}" is not a valid IPv6 address or range.`);
        if (mechanism === 'ptr') out.warnings.push('The "ptr" mechanism is deprecated (RFC 7208 §5.5) and slow; many receivers skip it.');
        if (mechanism === 'all') {
            out.all = qualifier;
            if (part !== parts[parts.length - 1]) out.warnings.push('Terms after "all" are never evaluated.');
        }
    }

    if (out.lookups > 10) out.errors.push(`This record needs ${out.lookups} DNS lookups before counting nested includes; the limit is 10 (RFC 7208 §4.6.4) and receivers return permerror.`);
    if (out.all === '+') {
        out.errors.push('"+all" authorises every server on the internet to send as this domain — SPF gives no protection.');
        out.recommendations.push('Replace "+all" with "~all" (soft fail) or "-all" (hard fail).');
    } else if (out.all === '?') {
        out.warnings.push('"?all" is neutral: unlisted senders are neither passed nor failed.');
        out.recommendations.push('Use "~all" or "-all" so unlisted senders fail SPF.');
    } else if (out.all === null && !out.modifiers.redirect) {
        out.warnings.push('The record has no "all" term and no redirect, so unlisted senders get a neutral result.');
        out.recommendations.push('End the record with "~all" or "-all".');
    } else if (out.all === '~') {
        out.recommendations.push('"~all" is a sound default. Once every legitimate sender is listed, "-all" tightens it further.');
    }
    return out;
}

// ── DMARC (RFC 7489) ──────────────────────────────────────────────────────────────────────

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';
export interface DmarcRecord extends Findings {
    exists: boolean;
    raw: string | null;
    tags: Record<string, string>;
    policy: DmarcPolicy | null;
    subdomainPolicy: DmarcPolicy | null;
    pct: number;
    rua: string[];
    ruf: string[];
    adkim: 'r' | 's';
    aspf: 'r' | 's';
}

const POLICIES = new Set(['none', 'quarantine', 'reject']);

export function parseDmarc(txtRecords: string[]): DmarcRecord {
    const recs = txtRecords.filter((t) => /^v\s*=\s*DMARC1\s*(;|$)/i.test(t.trim()));
    const out: DmarcRecord = {
        exists: recs.length > 0, raw: recs[0] ?? null, tags: {}, policy: null, subdomainPolicy: null,
        pct: 100, rua: [], ruf: [], adkim: 'r', aspf: 'r', ...findings(),
    };
    if (recs.length === 0) {
        out.errors.push('No DMARC record is published at _dmarc.<domain>.');
        out.recommendations.push('Start with "v=DMARC1; p=none; rua=mailto:<reports address>" to collect reports without affecting delivery, then move to quarantine and reject.');
        return out;
    }
    if (recs.length > 1) out.errors.push(`${recs.length} DMARC records are published. Receivers treat multiple records as no record at all (RFC 7489 §6.6.3).`);

    const pairs = recs[0].split(';').map((s) => s.trim()).filter(Boolean);
    pairs.forEach((pair, i) => {
        const eq = pair.indexOf('=');
        if (eq < 1) { out.errors.push(`"${pair}" is not a tag=value pair.`); return; }
        const k = pair.slice(0, eq).trim().toLowerCase();
        const v = pair.slice(eq + 1).trim();
        if (i === 0 && k !== 'v') out.errors.push('"v=DMARC1" must be the first tag.');
        if (out.tags[k] !== undefined) out.warnings.push(`Tag "${k}" appears more than once; only the first is used.`);
        else out.tags[k] = v;
    });

    const p = out.tags.p?.toLowerCase();
    if (!p) out.errors.push('The required "p" (policy) tag is missing, so the record is invalid.');
    else if (!POLICIES.has(p)) out.errors.push(`p=${out.tags.p} is not a valid policy (none, quarantine or reject).`);
    else out.policy = p as DmarcPolicy;

    const sp = out.tags.sp?.toLowerCase();
    if (sp !== undefined) {
        if (POLICIES.has(sp)) out.subdomainPolicy = sp as DmarcPolicy;
        else out.errors.push(`sp=${out.tags.sp} is not a valid subdomain policy.`);
    } else {
        out.subdomainPolicy = out.policy;
    }

    if (out.tags.pct !== undefined) {
        const pct = Number(out.tags.pct);
        if (!Number.isInteger(pct) || pct < 0 || pct > 100) out.errors.push(`pct=${out.tags.pct} must be a whole number from 0 to 100.`);
        else out.pct = pct;
    }
    for (const k of ['adkim', 'aspf'] as const) {
        const v = out.tags[k]?.toLowerCase();
        if (v === undefined) continue;
        if (v === 'r' || v === 's') out[k] = v;
        else out.errors.push(`${k}=${out.tags[k]} must be "r" (relaxed) or "s" (strict).`);
    }
    const uris = (v: string | undefined) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    out.rua = uris(out.tags.rua);
    out.ruf = uris(out.tags.ruf);
    for (const u of [...out.rua, ...out.ruf]) {
        if (!/^mailto:[^@\s]+@[^@\s]+/i.test(u)) out.errors.push(`"${u}" is not a mailto: address; reports cannot be delivered to it.`);
    }

    if (out.policy === 'none') {
        out.warnings.push('p=none only monitors: messages that fail DMARC are still delivered.');
        out.recommendations.push('Once reports show every legitimate sender passing, move to p=quarantine, then p=reject.');
    } else if (out.policy === 'quarantine') {
        out.recommendations.push('p=quarantine sends failing mail to spam. When reports stay clean, p=reject stops it entirely.');
    }
    if (out.policy && out.policy !== 'none' && out.pct < 100) {
        out.warnings.push(`pct=${out.pct}: the policy applies to only ${out.pct}% of failing messages.`);
    }
    if (out.rua.length === 0) {
        out.warnings.push('No "rua" address: you will receive no aggregate reports, so sending sources cannot be monitored.');
        out.recommendations.push('Add rua=mailto:<address> pointing at the NovrSOC DMARC report inbox.');
    }
    const rank = { none: 0, quarantine: 1, reject: 2 } as const;
    if (out.policy && out.subdomainPolicy && rank[out.subdomainPolicy] < rank[out.policy]) {
        out.warnings.push(`Subdomains use a weaker policy (sp=${out.subdomainPolicy}) than the domain (p=${out.policy}); attackers can spoof subdomains instead.`);
    }
    return out;
}

/** What each DMARC policy does, for the UI. */
export const POLICY_EXPLANATIONS: Record<DmarcPolicy, { title: string; effect: string; when: string }> = {
    none: {
        title: 'Monitor (p=none)',
        effect: 'Receivers deliver messages that fail DMARC as normal and send you reports.',
        when: 'Use first, while you discover every service that sends mail as your domain.',
    },
    quarantine: {
        title: 'Quarantine (p=quarantine)',
        effect: 'Receivers treat failing messages as suspicious — usually delivering them to spam.',
        when: 'Use once reports show your legitimate senders passing, to limit damage from spoofing while you confirm.',
    },
    reject: {
        title: 'Reject (p=reject)',
        effect: 'Receivers refuse failing messages outright; spoofed mail never reaches the inbox.',
        when: 'The goal state, once every legitimate source passes SPF or DKIM with alignment.',
    },
};

/** The record an administrator would publish to move to `policy`, keeping their other tags. */
export function buildDmarcRecord(current: DmarcRecord | null, policy: DmarcPolicy, ruaFallback?: string): string {
    const tags: [string, string][] = [['v', 'DMARC1'], ['p', policy]];
    const keep = current?.tags ?? {};
    for (const [k, v] of Object.entries(keep)) if (k !== 'v' && k !== 'p') tags.push([k, v]);
    if (!keep.rua && ruaFallback) tags.push(['rua', `mailto:${ruaFallback}`]);
    return tags.map(([k, v]) => `${k}=${v}`).join('; ');
}

// ── DKIM (RFC 6376) ───────────────────────────────────────────────────────────────────────

export interface DkimRecord extends Findings {
    selector: string;
    exists: boolean;
    raw: string | null;
    tags: Record<string, string>;
    keyType: string;
    keyBits: number | null;
    revoked: boolean;
    testing: boolean;
}

export function parseDkim(selector: string, txtRecords: string[]): DkimRecord {
    const recs = txtRecords.filter((t) => /(^|;)\s*p\s*=/i.test(t) || /^v\s*=\s*DKIM1/i.test(t.trim()));
    const out: DkimRecord = { selector, exists: recs.length > 0, raw: recs[0] ?? null, tags: {}, keyType: 'rsa', keyBits: null, revoked: false, testing: false, ...findings() };
    if (!out.raw) return out;

    const pairs = out.raw.split(';').map((s) => s.trim()).filter(Boolean);
    pairs.forEach((pair, i) => {
        const eq = pair.indexOf('=');
        if (eq < 1) { out.errors.push(`"${pair}" is not a tag=value pair.`); return; }
        const k = pair.slice(0, eq).trim().toLowerCase();
        const v = pair.slice(eq + 1).replace(/\s+/g, '');
        if (k === 'v' && i !== 0) out.errors.push('"v=DKIM1" must be the first tag when present.');
        out.tags[k] = v;
    });
    if (out.tags.v !== undefined && out.tags.v !== 'DKIM1') out.errors.push(`v=${out.tags.v} is not "DKIM1".`);
    out.keyType = (out.tags.k ?? 'rsa').toLowerCase();
    if (!['rsa', 'ed25519'].includes(out.keyType)) out.errors.push(`Key type k=${out.tags.k} is not rsa or ed25519.`);
    out.testing = (out.tags.t ?? '').split(':').includes('y');
    if (out.testing) out.warnings.push('t=y (testing mode): receivers may treat signatures as unsigned.');

    const p = out.tags.p;
    if (p === undefined) { out.errors.push('The required "p" (public key) tag is missing.'); return out; }
    if (p === '') { out.revoked = true; out.warnings.push('The key is revoked (empty p=). Mail signed with this selector fails DKIM.'); return out; }
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(p)) { out.errors.push('The public key is not valid base64.'); return out; }

    if (out.keyType === 'rsa') {
        try {
            const key = createPublicKey({ key: Buffer.from(p, 'base64'), format: 'der', type: 'spki' });
            out.keyBits = key.asymmetricKeyDetails?.modulusLength ?? null;
        } catch {
            out.errors.push('The public key could not be decoded as an RSA key.');
            return out;
        }
        if (out.keyBits !== null && out.keyBits < 1024) out.errors.push(`${out.keyBits}-bit RSA keys are too short to be trusted (RFC 8301 requires at least 1024).`);
        else if (out.keyBits === 1024) {
            out.warnings.push('1024-bit RSA key: still accepted, but 2048-bit is the current recommendation.');
            out.recommendations.push('Rotate this selector to a 2048-bit key.');
        }
    }
    return out;
}

/** Selectors published by common mail services — DKIM can't be discovered without the selector. */
export const COMMON_DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'mail', 'dkim', 'smtp',
    'mandrill', 'mxvault', 'zoho', 'zmail', 'protonmail', 'protonmail2', 'protonmail3', 'sig1', 'mailjet',
    'sendgrid', 'smtpapi', 'fm1', 'fm2', 'fm3', 'resend', 'mta', 'brevo', 'mailo', 'amazonses', 'everlytickey1',
];

// ── Health score ──────────────────────────────────────────────────────────────────────────

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'missing' | 'not_found' | 'error';

export function spfStatus(spf: SpfRecord): CheckStatus {
    if (!spf.exists) return 'missing';
    if (spf.errors.length) return 'fail';
    return spf.warnings.length ? 'warn' : 'pass';
}
export function dmarcStatus(d: DmarcRecord): CheckStatus {
    if (!d.exists) return 'missing';
    if (d.errors.length || !d.policy) return 'fail';
    return d.policy === 'none' || d.warnings.length ? 'warn' : 'pass';
}
export function dkimStatus(found: DkimRecord[]): CheckStatus {
    const live = found.filter((k) => k.exists && !k.revoked);
    if (live.length === 0) return 'not_found';
    if (live.every((k) => k.errors.length)) return 'fail';
    return live.some((k) => k.warnings.length || k.errors.length) ? 'warn' : 'pass';
}

export interface HealthPart { label: string; points: number; max: number }
/** 0–100 with the breakdown shown to the user — no score without its reasons. */
export function authenticationHealth(spf: SpfRecord, dmarc: DmarcRecord, dkim: DkimRecord[]): { score: number; parts: HealthPart[] } {
    const parts: HealthPart[] = [
        { label: 'SPF published and valid', max: 25, points: spf.exists && !spf.errors.length ? 25 : spf.exists ? 10 : 0 },
        { label: 'SPF fails unlisted senders (~all / -all)', max: 10, points: spf.all === '-' || spf.all === '~' ? 10 : 0 },
        { label: 'DMARC published and valid', max: 20, points: dmarc.exists && !dmarc.errors.length && dmarc.policy ? 20 : 0 },
        { label: 'DMARC enforcement (quarantine / reject)', max: 20, points: dmarc.policy === 'reject' ? 20 : dmarc.policy === 'quarantine' ? 12 : 0 },
        { label: 'DMARC aggregate reports (rua)', max: 5, points: dmarc.rua.length ? 5 : 0 },
        // DKIM that simply wasn't found under the probed selectors scores nothing rather than a
        // penalty — it may well be published under a selector we don't know.
        { label: 'DKIM key found and valid', max: 20, points: dkimStatus(dkim) === 'pass' ? 20 : dkimStatus(dkim) === 'warn' ? 12 : 0 },
    ];
    return { score: parts.reduce((s, p) => s + p.points, 0), parts };
}

export function domainStatusFromScore(score: number): 'healthy' | 'warning' | 'critical' {
    return score >= 80 ? 'healthy' : score >= 50 ? 'warning' : 'critical';
}
