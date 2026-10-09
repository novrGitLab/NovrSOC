// Redaction for data leaving NovrSOC through the vendor export API (phase X1).
//
// Stored alert content (raw, including full_log) is untrusted log text that can carry credentials.
// Before any of it is exported, every string goes through redactString() and every object key that
// names a secret has its whole value masked.
//
// 'standard' profile masks:
//   • values of keys containing password / passwd / secret / token / api_key / api-key / apikey /
//     authorization — in key=value, key: value, "key":"value", 'key'='value', ?key=value&…,
//     backslash-escaped JSON, and as object keys in structured data
//   • a whole Authorization header value (scheme + credentials, e.g. "Basic …", "Bearer …")
//   • bearer tokens anywhere ("Bearer <token>")
//   • command-line flags naming a secret followed by a value (--password x, -token "y", /apikey z)
//   • PEM private key blocks (also an unterminated BEGIN … PRIVATE KEY to the end of the text)
//
// Never throws. If redaction fails for a value, that value is dropped (null / omitted) rather
// than returned unredacted. The patterns are linear: keys only match from the start of a token,
// and no pattern has nested quantifiers, so hostile input can't cause catastrophic backtracking.

export const REDACTED = '[REDACTED]';

/** Key names whose values are secrets (matched case-insensitively anywhere in the key). */
const SECRET_KEY = /password|passwd|secret|token|api[_-]?key|authorization/i;

// "-----BEGIN RSA PRIVATE KEY----- … -----END RSA PRIVATE KEY-----", or to the end if unterminated.
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)/g;

// Authorization header/field: mask the entire value (scheme and credentials) up to a line end,
// a closing quote or a separator.
const AUTH_HEADER = /(authorization\\?["']?\s*[:=]\s*)(\\?["']?)[^\r\n"'\\,;&}]*/gi;

const BEARER = /\b(bearer)(\s+)[A-Za-z0-9\-._~+/]+=*/gi;

// key<sep>value. The key is a token that starts after a non-token character (lookbehind), so
// each token is tried once. Value forms: "…", '…', \"…\" (escaped JSON), or a bare run.
const KEY_VALUE = new RegExp(
    String.raw`(?<![A-Za-z0-9_.\-])([A-Za-z0-9_.\-]{1,128})(\\?["']?)(\s*[:=]\s*)` +
    String.raw`("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\\"(?:[^"\\]|\\[^"])*\\"|[^\s&,;"'}\]\\]+)`,
    'g',
);

// What an earlier pass leaves behind (a bare run stops at ']'). Only these exact forms are skipped,
// so a real secret that merely contains the word REDACTED is still masked.
const ALREADY_MASKED = new Set([REDACTED, '[REDACTED', `"${REDACTED}"`, `'${REDACTED}'`, `\\"${REDACTED}\\"`]);

// Command-line flags with a space before the value: --password hunter2, -token "abc", /apikey x.
// Only dash/slash-prefixed flags, so prose like "Failed password for root" is left alone.
const CLI_FLAG = /(?<![A-Za-z0-9_.\-])((?:--?|\/)[A-Za-z0-9_.\-]{1,128})(\s+)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s"']+)/g;

function maskQuoted(value: string): string {
    if (value.startsWith('\\"')) return `\\"${REDACTED}\\"`;
    if (value.startsWith('"')) return `"${REDACTED}"`;
    if (value.startsWith("'")) return `'${REDACTED}'`;
    return REDACTED;
}

/** Redacts one string. null = redaction failed; the caller must drop the value. */
export function redactString(input: string): string | null {
    try {
        if (typeof input !== 'string') return null;
        let s = input.replace(PRIVATE_KEY_BLOCK, `${REDACTED} PRIVATE KEY`);
        s = s.replace(AUTH_HEADER, (_m, head: string, quote: string) => `${head}${quote}${REDACTED}`);
        s = s.replace(BEARER, (_m, word: string, space: string) => `${word}${space}${REDACTED}`);
        s = s.replace(KEY_VALUE, (m, key: string, q: string, sep: string, value: string) =>
            SECRET_KEY.test(key) && !ALREADY_MASKED.has(value) ? `${key}${q}${sep}${maskQuoted(value)}` : m);
        s = s.replace(CLI_FLAG, (m, flag: string, space: string, value: string) =>
            SECRET_KEY.test(flag) && !ALREADY_MASKED.has(value) && !value.startsWith('-') ? `${flag}${space}${maskQuoted(value)}` : m);
        return s;
    } catch {
        return null;
    }
}

const MAX_DEPTH = 64;

function walk(v: unknown, depth: number): unknown {
    if (depth > MAX_DEPTH) throw new Error('too deep');
    if (typeof v === 'string') {
        const r = redactString(v);
        if (r === null) throw new Error('string redaction failed');
        return r;
    }
    if (v === null || typeof v === 'number' || typeof v === 'boolean') return v;
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    if (typeof v === 'object') {
        const out: Record<string, unknown> = {};
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
            out[k] = SECRET_KEY.test(k) ? REDACTED : walk(val, depth + 1);
        }
        return out;
    }
    return null; // undefined, functions, symbols, bigint: nothing to export
}

/**
 * Redacts every string in a JSON-like value and masks the value of every secret-named key.
 * undefined = redaction failed; the caller must omit the field.
 */
export function redactValue(v: unknown): unknown {
    try {
        return walk(v, 0);
    } catch {
        return undefined;
    }
}

export const REDACTION_PROFILES = ['standard', 'no_raw'] as const;
export type RedactionProfile = (typeof REDACTION_PROFILES)[number];

/** Whether a profile exports `raw` at all. Unknown profiles export nothing extra (fail safe). */
export const profileIncludesRaw = (profile: string | null | undefined) => profile === 'standard';
