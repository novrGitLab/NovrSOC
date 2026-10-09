// Phish ID risk classification. Every point in the score comes from a named signal with the
// evidence behind it, and the UI shows the list — so an analyst can always see WHY a domain
// is rated what it is, and disagree with a specific signal rather than a number.
//
// Similarity alone never makes a domain more than "low": look-alike registrations are common
// and often harmless. Risk rises only with evidence of phishing behaviour or intelligence hits.
import type { Resemblance } from './similarity';
import type { WebsiteEvidence } from './siteInspect';
import { emailsecConfig } from './config';
import { severityFromScore } from '../../lib/severity';

export type Risk = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export const RISK_ORDER: Risk[] = ['informational', 'low', 'medium', 'high', 'critical'];
export const riskAtLeast = (r: Risk, min: Risk) => RISK_ORDER.indexOf(r) >= RISK_ORDER.indexOf(min);

export interface RiskSignal { id: string; label: string; detail: string; points: number }
export interface RiskInput {
    resemblance: Resemblance | null;
    domain_age_days: number | null;
    resolves: boolean | null;
    website: WebsiteEvidence | null;
    ti_hits: string[];           // e.g. ["OpenPhish: listed as phishing"]
    brand_terms: string[];
}

export function assessPhishingRisk(i: RiskInput): { risk: Risk; score: number; signals: RiskSignal[]; summary: string } {
    const s: RiskSignal[] = [];
    const add = (id: string, label: string, detail: string, points: number) => s.push({ id, label, detail, points });

    if (i.resemblance) {
        const t = i.resemblance.techniques;
        if (t.includes('homoglyph')) add('homoglyph', 'Visually identical to your domain', i.resemblance.reasons.join(' '), 20);
        else if (t.includes('replacement') || t.includes('tld_swap') || t.includes('hyphenation')) add('lookalike', 'Look-alike of your domain', i.resemblance.reasons.join(' '), 12);
        if (t.includes('keyword')) add('brand_keyword', 'Uses your brand name in the domain', i.resemblance.reasons.find((r) => /brand/i.test(r)) ?? '', 12);
    }
    const young = emailsecConfig.youngDomainDays();
    if (i.domain_age_days !== null && i.domain_age_days <= young) add('young_domain', 'Newly registered', `Registered ${i.domain_age_days} day${i.domain_age_days === 1 ? '' : 's'} ago`, 15);
    for (const hit of i.ti_hits) add('threat_intel', 'Threat-intelligence match', hit, 45);

    const w = i.website;
    if (w?.reachable) {
        const pw = w.forms.some((f) => f.password_fields > 0) || w.login_indicators.includes('password field');
        if (pw) add('login_form', 'Login form (password field)', 'The page asks for a password.', 20);
        else if (w.login_indicators.length) add('login_language', 'Login / verification wording', w.login_indicators.slice(0, 4).join(', '), 8);
        if (w.brand_mentions.length) add('brand_on_page', 'Your brand appears on the page', w.brand_mentions.join(', '), 15);
        const ext = w.forms.find((f) => f.external);
        if (ext) add('external_form', 'Form sends data to another site', ext.action ?? '', 15);
        if (w.cross_domain_redirect) add('redirect', 'Redirects to a different domain', w.final_url ?? '', 8);
        if (w.tls && !w.tls.authorized) add('bad_tls', 'Invalid TLS certificate', w.tls.authorization_error ?? 'certificate not trusted', 5);
        if (pw && w.brand_mentions.length) add('credential_harvest', 'Brand + credential capture on a look-alike domain', 'The combination typical of a credential-phishing kit.', 15);
    }

    const score = s.reduce((a, x) => a + x.points, 0);
    let risk: Risk = score > 0 ? severityFromScore(score) : 'informational';
    // Guard rails: an intelligence listing is at least high; similarity with no behaviour caps at low.
    if (i.ti_hits.length && !riskAtLeast(risk, 'high')) risk = 'high';
    const behaviour = s.some((x) => ['login_form', 'brand_on_page', 'external_form', 'threat_intel', 'credential_harvest', 'young_domain'].includes(x.id));
    if (!behaviour && riskAtLeast(risk, 'medium')) risk = 'low';

    const summary = s.length === 0
        ? 'No risk signals found.'
        : `${risk[0].toUpperCase()}${risk.slice(1)} risk: ${s.map((x) => x.label.toLowerCase()).join('; ')}.`;
    return { risk, score, signals: s, summary };
}

/** Case / alert severity for a risk level. */
export function severityForRisk(r: Risk): 'low' | 'medium' | 'high' | 'critical' {
    return r === 'critical' ? 'critical' : r === 'high' ? 'high' : r === 'medium' ? 'medium' : 'low';
}
