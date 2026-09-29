// Lookalike-domain engine for Phish ID: generates typosquatting candidates for a protected
// domain and explains how any observed domain resembles it. Pure functions, unit-tested.
//
// Generating a candidate says nothing about whether it is malicious — most permutations are
// unregistered, and many registered ones are parked or legitimate. Discovery only records the
// ones that exist; risk comes later from evidence (phishRisk.ts).
import { domainToASCII, domainToUnicode } from 'url';

// Public suffixes that take a second label (so "bank.com.ng" splits as bank + com.ng). Not the
// full Public Suffix List — the common ones for this platform's customers.
const MULTI_SUFFIXES = new Set([
    'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng', 'name.ng', 'sch.ng', 'mil.ng',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.za', 'org.za',
    'co.ke', 'or.ke', 'com.gh', 'org.gh', 'co.in', 'com.br', 'com.mx', 'co.jp', 'com.sg', 'com.tr',
]);

export interface SplitDomain { label: string; suffix: string; subdomain: string }

export function splitDomain(domain: string): SplitDomain {
    const parts = domain.toLowerCase().replace(/\.$/, '').split('.');
    const two = parts.slice(-2).join('.');
    const suffixLen = parts.length > 2 && MULTI_SUFFIXES.has(two) ? 2 : 1;
    const suffix = parts.slice(-suffixLen).join('.');
    const label = parts[parts.length - suffixLen - 1] ?? '';
    return { label, suffix, subdomain: parts.slice(0, parts.length - suffixLen - 1).join('.') };
}

/** The registrable domain (label + public suffix), e.g. login.bank.com.ng → bank.com.ng. */
export function registrableDomain(domain: string): string {
    const { label, suffix } = splitDomain(domain);
    return label ? `${label}.${suffix}` : suffix;
}

// ── Distance ───────────────────────────────────────────────────────────────────────────────

/** Damerau–Levenshtein (optimal string alignment) distance. */
export function editDistance(a: string, b: string): number {
    const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
            if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
    }
    return d[a.length][b.length];
}

// ── Homoglyphs ─────────────────────────────────────────────────────────────────────────────

// Unicode confusables → the ASCII letter they imitate (Cyrillic, Greek, Latin variants).
const UNICODE_CONFUSABLES: Record<string, string> = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'κ': 'k', 'ι': 'i', 'ε': 'e',
    'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
    'ç': 'c', 'ñ': 'n', 'ý': 'y', 'ł': 'l', 'ı': 'i', 'ʀ': 'r',
};
// ASCII sequences that read as another letter at a glance.
const ASCII_CONFUSABLES: [string, string][] = [['rn', 'm'], ['vv', 'w'], ['cl', 'd'], ['0', 'o'], ['1', 'l'], ['3', 'e'], ['5', 's'], ['8', 'b'], ['i', 'l']];

/** Collapse a label to its visual skeleton: two labels with the same skeleton look alike. */
export function skeleton(label: string): string {
    let s = [...domainToUnicode(label) || label].map((ch) => UNICODE_CONFUSABLES[ch] ?? ch).join('');
    for (const [from, to] of ASCII_CONFUSABLES) s = s.split(from).join(to);
    return s;
}

export function isHomoglyphOf(candidateLabel: string, brandLabel: string): boolean {
    return candidateLabel !== brandLabel && skeleton(candidateLabel) === skeleton(brandLabel);
}

// ── Candidate generation ───────────────────────────────────────────────────────────────────

export type Technique =
    | 'omission' | 'repetition' | 'transposition' | 'replacement' | 'insertion' | 'homoglyph'
    | 'hyphenation' | 'vowel_swap' | 'tld_swap' | 'keyword' | 'subdomain_split';

export interface Candidate { domain: string; technique: Technique }

const KEYBOARD: Record<string, string> = {
    q: 'wa', w: 'qeas', e: 'wrds', r: 'etdf', t: 'ryfg', y: 'tugh', u: 'yihj', i: 'uojk', o: 'ipkl', p: 'ol',
    a: 'qwsz', s: 'awedxz', d: 'serfcx', f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', j: 'huikmn', k: 'jiolm', l: 'kop',
    z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk',
};
const VOWELS = 'aeiou';
const ASCII_HOMOGLYPH_SWAPS: [string, string][] = [['o', '0'], ['l', '1'], ['i', '1'], ['m', 'rn'], ['w', 'vv'], ['d', 'cl'], ['e', '3'], ['s', '5'], ['i', 'l'], ['l', 'i']];
const IDN_SWAPS: [string, string][] = [['a', 'а'], ['e', 'е'], ['o', 'о'], ['p', 'р'], ['c', 'с'], ['x', 'х'], ['y', 'у'], ['i', 'і']];
const ALT_TLDS = ['com', 'net', 'org', 'co', 'io', 'ng', 'com.ng', 'info', 'online', 'site', 'xyz', 'app', 'biz', 'live', 'support'];
export const PHISH_KEYWORDS = ['login', 'secure', 'support', 'verify', 'account', 'online', 'portal', 'mail', 'auth', 'update', 'service', 'help', 'bank', 'pay', 'signin', 'security'];

const VALID_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export function generateCandidates(domain: string, limit = 400): Candidate[] {
    const { label, suffix } = splitDomain(domain);
    const out = new Map<string, Technique>();
    const add = (l: string, technique: Technique, sfx = suffix) => {
        const ascii = domainToASCII(l);
        if (!ascii || !VALID_LABEL.test(ascii)) return;
        const d = `${ascii}.${sfx}`;
        if (d !== domain && !out.has(d)) out.set(d, technique);
    };

    for (let i = 0; i < label.length; i++) {
        add(label.slice(0, i) + label.slice(i + 1), 'omission');
        add(label.slice(0, i) + label[i] + label.slice(i), 'repetition');
        if (i < label.length - 1) add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), 'transposition');
        for (const k of KEYBOARD[label[i]] ?? '') {
            add(label.slice(0, i) + k + label.slice(i + 1), 'replacement');
            add(label.slice(0, i) + k + label.slice(i), 'insertion');
        }
        if (VOWELS.includes(label[i])) for (const v of VOWELS) if (v !== label[i]) add(label.slice(0, i) + v + label.slice(i + 1), 'vowel_swap');
        if (i > 0) add(`${label.slice(0, i)}-${label.slice(i)}`, 'hyphenation');
        if (i > 0) out.set(`${label.slice(0, i)}.${label.slice(i)}.${suffix}`, out.get(`${label.slice(0, i)}.${label.slice(i)}.${suffix}`) ?? 'subdomain_split');
    }
    for (const [from, to] of ASCII_HOMOGLYPH_SWAPS) {
        let idx = label.indexOf(from);
        while (idx >= 0) { add(label.slice(0, idx) + to + label.slice(idx + from.length), 'homoglyph'); idx = label.indexOf(from, idx + 1); }
    }
    for (const [from, to] of IDN_SWAPS) {
        const idx = label.indexOf(from);
        if (idx >= 0) add(label.slice(0, idx) + to + label.slice(idx + 1), 'homoglyph');
    }
    for (const kw of PHISH_KEYWORDS) {
        add(`${label}-${kw}`, 'keyword'); add(`${kw}-${label}`, 'keyword'); add(`${label}${kw}`, 'keyword'); add(`${kw}${label}`, 'keyword');
    }
    for (const t of ALT_TLDS) if (t !== suffix) add(label, 'tld_swap', t);

    // Stable priority: the techniques most used in real campaigns first, so a limit keeps them.
    const priority: Technique[] = ['homoglyph', 'keyword', 'tld_swap', 'omission', 'transposition', 'replacement', 'repetition', 'hyphenation', 'vowel_swap', 'insertion', 'subdomain_split'];
    return [...out.entries()]
        .map(([d, technique]) => ({ domain: d, technique }))
        .sort((a, b) => priority.indexOf(a.technique) - priority.indexOf(b.technique))
        .slice(0, limit);
}

// ── Explaining an observed domain ──────────────────────────────────────────────────────────

export interface Resemblance { brand_domain: string; techniques: Technique[]; similarity: number; reasons: string[] }

/** How `observed` resembles `brandDomain`, or null if it doesn't meaningfully. */
export function resemblance(observed: string, brandDomain: string, keywords: string[] = []): Resemblance | null {
    const o = splitDomain(observed);
    const b = splitDomain(brandDomain);
    if (!o.label || !b.label) return null;
    if (registrableDomain(observed) === registrableDomain(brandDomain)) return null; // the brand's own domain / subdomain
    const oLabel = domainToUnicode(o.label) || o.label;
    const techniques = new Set<Technique>();
    const reasons: string[] = [];

    const dist = editDistance(o.label, b.label);
    const sim = 1 - dist / Math.max(o.label.length, b.label.length);
    if (o.label === b.label && o.suffix !== b.suffix) { techniques.add('tld_swap'); reasons.push(`Same name as ${brandDomain} under a different extension (.${o.suffix}).`); }
    if (isHomoglyphOf(oLabel, b.label) || (o.label.startsWith('xn--') && skeleton(oLabel) === skeleton(b.label))) {
        techniques.add('homoglyph'); reasons.push(`"${oLabel}" is visually identical to "${b.label}" (look-alike characters).`);
    } else if (dist > 0 && dist <= (b.label.length >= 8 ? 2 : 1)) {
        techniques.add('replacement'); reasons.push(`"${o.label}" is ${dist} character${dist === 1 ? '' : 's'} away from "${b.label}" (typo).`);
    }
    const stripped = o.label.replace(/-/g, '');
    if (stripped !== o.label && stripped === b.label) { techniques.add('hyphenation'); reasons.push(`"${o.label}" is "${b.label}" with hyphens added.`); }
    if (o.label !== b.label && o.label.includes(b.label)) {
        const kw = PHISH_KEYWORDS.find((k) => o.label.includes(k));
        techniques.add('keyword');
        reasons.push(kw ? `Contains the brand name "${b.label}" plus "${kw}", a common phishing lure.` : `Contains the brand name "${b.label}".`);
    }
    for (const k of keywords.map((x) => x.toLowerCase()).filter((x) => x.length >= 4)) {
        if (o.label.includes(k.replace(/\s+/g, '')) && !techniques.has('keyword')) { techniques.add('keyword'); reasons.push(`Contains the brand keyword "${k}".`); }
    }
    if (o.subdomain && o.subdomain.includes(b.label)) { techniques.add('subdomain_split'); reasons.push(`Uses "${b.label}" as a subdomain of an unrelated domain.`); }

    if (techniques.size === 0) return null;
    return { brand_domain: brandDomain, techniques: [...techniques], similarity: Math.round(Math.max(sim, techniques.has('homoglyph') ? 0.99 : 0) * 100) / 100, reasons };
}
