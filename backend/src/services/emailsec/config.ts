// Email Security detection settings. Every threshold that decides a severity or an alert is
// here and overridable by environment variable, so detection logic is configurable without a
// code change and nothing is a magic number buried in a service.

const num = (name: string, fallback: number): number => {
    const v = Number(process.env[name]);
    return Number.isFinite(v) && v >= 0 ? v : fallback;
};

export const emailsecConfig = {
    /** A DMARC sending source that fails every message is "suspicious" once it has sent this many. */
    spoofMinMessages: () => num('EMAILSEC_SPOOF_MIN_MESSAGES', 5),
    /** …and the spoofing alert becomes high severity at this many (or whenever p=none let them through). */
    spoofHighMessages: () => num('EMAILSEC_SPOOF_HIGH_MESSAGES', 50),
    /** Phish ID: domains younger than this many days score the "newly registered" signal. */
    youngDomainDays: () => num('EMAILSEC_YOUNG_DOMAIN_DAYS', 30),
    /** Phish ID: an alert is raised when a discovered domain reaches this risk level. */
    phishAlertMinRisk: () => (process.env.EMAILSEC_PHISH_ALERT_MIN_RISK ?? 'high') as 'low' | 'medium' | 'high' | 'critical',
    /** Phish ID: at most this many permutation candidates are resolved per protected domain per run. */
    maxCandidatesPerDomain: () => num('EMAILSEC_MAX_CANDIDATES', 400),
    /** OpenCTI: only findings at or above this confidence (0–100) are ever pushed. */
    openctiMinConfidence: () => num('OPENCTI_MIN_CONFIDENCE', 75),
    /** Background job intervals (minutes). */
    dnsCheckMinutes: () => num('EMAILSEC_DNS_CHECK_MINUTES', 360),
    discoveryMinutes: () => num('EMAILSEC_DISCOVERY_MINUTES', 1440),
    enrichMinutes: () => num('EMAILSEC_ENRICH_MINUTES', 60),
    syncMinutes: () => num('EMAILSEC_SYNC_MINUTES', 10),
};
