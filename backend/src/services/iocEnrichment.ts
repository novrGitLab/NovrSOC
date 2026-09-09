// Unified IOC enrichment — combines all threat intel sources.
// Called by CTI Platform, Threat Management, URL Scan Suite (via routes/threat.ts).

import { checkIP, type AbuseIPDBResult } from './abuseipdb';
import { urlhausLookupURL, urlhausLookupHost, type URLHausResult, type URLHausHostResult } from './urlhaus';
import { threatfoxSearchIOC, type ThreatFoxIOC } from './threatfox';
import { vtCheckIP, vtCheckDomain, vtCheckHash, vtCheckURL, vtToRiskScore, type VTResult } from './virustotal';
import { checkGreyNoise, type GreyNoiseResult } from './greynoise';
import { checkLeakIX, type LeakIXResult } from './leakix';
import { searchMISP, mispEventUrl } from './misp';

// OTX and Censys were removed from this pipeline (2026-09-09). OTX's pulse contribution is now
// covered by ThreatFox (which has a working key here) plus the keyless CIRCL OSINT feed for the
// pulse/advisory surfaces; Censys's host-exposure role is now LeakIX's.

export type IOCType = 'ip' | 'domain' | 'hash' | 'url';

export interface EnrichedIOC {
    value: string;
    type: IOCType;
    risk_score: number;          // 0-100 composite
    verdict: 'clean' | 'suspicious' | 'malicious';
    sources: {
        abuseipdb: { confidence: number; total_reports: number; country: string | null; isp: string | null; is_tor: boolean } | null;
        urlhaus: { status: string; threat: string; tags: string[] } | null;
        threatfox: { malware: string; confidence: number; threat_type: string } | null;
        virustotal: { malicious: number; suspicious: number; total_engines: number; verdict: string; as_owner: string | undefined; tags: string[] } | null;
        greynoise: { noise: boolean; riot: boolean; classification: string; name?: string } | null;
        // Host exposure from LeakIX. `status` distinguishes a real "no records" from "we never
        // asked" (no key) or "the lookup failed" — an unconfigured LeakIX must never read as a
        // clean host. Open services are informational; confirmed leaks do move the risk score.
        leakix: { status: LeakIXResult['status']; exposed: boolean; service_count: number; leak_count: number; services: LeakIXResult['services']; leaks: LeakIXResult['leaks'] } | null;
        // A hit here means this exact value is already in the org's own MISP — the strongest
        // signal available, because someone deliberately curated it rather than it coming from
        // a third-party feed. Null when MISP isn't configured, is unreachable, or has no match.
        misp: {
            count: number;
            events: string[];
            attributes: Array<{ type?: string; value?: string; category?: string; event_id?: string; comment?: string }>;
            event_links: Array<{ event_id: string; url: string }>;
        } | null;
    };
    tags: string[];
    enriched_at: string;
}

function urlhausSummary(result: URLHausResult | URLHausHostResult | null): { status: string; threat: string; tags: string[] } | null {
    if (!result) return null;
    if ('url_status' in result) {
        // Single-URL lookup (urlhausLookupURL)
        return { status: result.url_status, threat: result.threat, tags: result.tags ?? [] };
    }
    // Host lookup (urlhausLookupHost) — summarize from the most recent URL on this host, if any
    const first = result.urls?.[0];
    if (!first) return null;
    return { status: first.url_status, threat: first.threat, tags: first.tags ?? [] };
}

export async function enrichIOC(value: string, type: IOCType): Promise<EnrichedIOC> {
    const abuseLookup: Promise<AbuseIPDBResult | null> = type === 'ip' ? checkIP(value) : Promise.resolve(null);

    const urlhausLookup: Promise<URLHausResult | URLHausHostResult | null> =
        type === 'url' ? urlhausLookupURL(value)
        : type === 'domain' ? urlhausLookupHost(value)
        : Promise.resolve(null);

    const threatfoxLookup: Promise<ThreatFoxIOC[]> = threatfoxSearchIOC(value);

    const vtLookup: Promise<VTResult | null> =
        type === 'ip' ? vtCheckIP(value)
        : type === 'domain' ? vtCheckDomain(value)
        : type === 'hash' ? vtCheckHash(value)
        : vtCheckURL(value);

    // GreyNoise only makes sense for IPs (it's internet-scan telemetry) — a no-key call for
    // every other type would just waste a request on a value it was never going to answer for.
    const greynoiseLookup: Promise<GreyNoiseResult | null> = type === 'ip' ? checkGreyNoise(value) : Promise.resolve(null);
    // Host exposure — IP-only, same reasoning as GreyNoise above. Open ports alone are
    // informational, but a confirmed leak is a finding and does feed the risk score.
    const leakixLookup: Promise<LeakIXResult | null> = type === 'ip' ? checkLeakIX(value) : Promise.resolve(null);

    // MISP applies to every IOC type — it stores whatever the org has curated, not one class of
    // indicator. Returns null (never throws) when unconfigured or when the key is rejected.
    const mispLookup = searchMISP(value);

    const [abuseResult, urlhausResult, threatfoxResult, vtResult, greynoiseResult, leakixResult, mispResult] = await Promise.allSettled([
        abuseLookup, urlhausLookup, threatfoxLookup, vtLookup, greynoiseLookup, leakixLookup, mispLookup,
    ]);

    const abuse = abuseResult.status === 'fulfilled' ? abuseResult.value : null;
    const urlhaus = urlhausSummary(urlhausResult.status === 'fulfilled' ? urlhausResult.value : null);
    const threatfox = threatfoxResult.status === 'fulfilled' ? threatfoxResult.value : [];
    const vt = vtResult.status === 'fulfilled' ? vtResult.value : null;
    const greynoise = greynoiseResult.status === 'fulfilled' && !greynoiseResult.value?.error ? greynoiseResult.value : null;
    const leakix = leakixResult.status === 'fulfilled' ? leakixResult.value : null;
    const misp = mispResult.status === 'fulfilled' ? mispResult.value : null;

    // Composite risk score
    let score = 0;
    if (abuse && abuse.abuseConfidenceScore) score += Math.floor(abuse.abuseConfidenceScore * 0.3); // up to 30 from AbuseIPDB
    if (urlhaus) score += 25; // known malicious URL/host
    if (threatfox.length > 0) {
        // ThreatFox absorbs the weight OTX used to carry here: it's now the primary
        // pulse/campaign-style corroboration, so it contributes up to 40 rather than 20.
        const maxConf = Math.max(...threatfox.map((t) => t.confidence_level || 0));
        score += Math.min(40, Math.floor(maxConf * 0.4));
    }
    score += vtToRiskScore(vt); // up to 35 from VirusTotal
    // GreyNoise adjusts rather than adds to the base score — it's context (is this address
    // mass-scanning, or a known-benign business service?), not an independent detection engine
    // the way OTX/AbuseIPDB/VirusTotal are.
    if (greynoise?.classification === 'malicious') score = Math.min(100, score + 20);
    if (greynoise?.riot) score = Math.max(0, score - 10);
    // A confirmed leak on the host is a concrete finding, not just surface area, so it moves the
    // score. Only counted for a status:'ok' answer — an unconfigured or failed LeakIX lookup
    // must never change the score in either direction.
    if (leakix?.status === 'ok' && leakix.leaks.length > 0) score = Math.min(100, score + 15);
    // A MISP hit is the org's own curated intelligence — weighted above any single external
    // feed, but still additive rather than an automatic 100, so a stale MISP entry can't by
    // itself outrank every other source saying the value is clean.
    if (misp?.found) score = Math.min(100, score + 25);
    score = Math.min(100, score);

    const verdict: EnrichedIOC['verdict'] = score >= 70 ? 'malicious' : score >= 30 ? 'suspicious' : 'clean';

    // Collect tags
    const tags = new Set<string>();
    if (abuse?.isTor) tags.add('tor');
    if (abuse?.usageType) tags.add(abuse.usageType.toLowerCase().replace(/\s+/g, '-'));
    urlhaus?.tags.forEach((t) => tags.add(t));
    threatfox.forEach((t) => t.tags?.forEach((tag) => tags.add(tag)));
    vt?.tags?.forEach((tag) => tags.add(tag));
    if (greynoise?.noise) tags.add('internet-scanner');
    if (greynoise?.riot) tags.add('known-benign-service');
    greynoise?.tags?.forEach((tag) => tags.add(tag));
    if (leakix?.status === 'ok' && leakix.leaks.length > 0) tags.add('known-leak');
    if (leakix?.status === 'ok' && leakix.services.length > 0) tags.add('exposed-service');
    if (misp?.found) tags.add('in-misp');

    return {
        value,
        type,
        risk_score: score,
        verdict,
        sources: {
            abuseipdb: abuse ? {
                confidence: abuse.abuseConfidenceScore,
                total_reports: abuse.totalReports,
                country: abuse.countryCode,
                isp: abuse.isp,
                is_tor: abuse.isTor,
            } : null,
            urlhaus,
            threatfox: threatfox.length > 0 ? {
                malware: threatfox[0].malware_printable,
                confidence: threatfox[0].confidence_level,
                threat_type: threatfox[0].threat_type,
            } : null,
            virustotal: vt ? {
                malicious: vt.stats.malicious,
                suspicious: vt.stats.suspicious,
                total_engines: vt.stats.malicious + vt.stats.suspicious + vt.stats.undetected + vt.stats.harmless,
                verdict: vt.verdict,
                as_owner: vt.as_owner,
                tags: vt.tags || [],
            } : null,
            greynoise: greynoise ? {
                noise: greynoise.noise,
                riot: greynoise.riot,
                classification: greynoise.classification,
                name: greynoise.name,
            } : null,
            leakix: leakix ? {
                status: leakix.status,
                exposed: leakix.exposed,
                service_count: leakix.services.length,
                leak_count: leakix.leaks.length,
                services: leakix.services,
                leaks: leakix.leaks,
            } : null,
            misp: misp?.found
                ? {
                    count: misp.count,
                    events: misp.events,
                    attributes: misp.attributes,
                    // Built from MISP_BROWSE_URL (falling back to MISP_URL) rather than assembled
                    // in the frontend — see services/misp.ts on why those two differ.
                    event_links: misp.events
                        .map((id) => ({ event_id: id, url: mispEventUrl(id) }))
                        .filter((l): l is { event_id: string; url: string } => l.url !== null),
                }
                : null,
        },
        tags: [...tags],
        enriched_at: new Date().toISOString(),
    };
}
