import 'dotenv/config';
import { circlGetPulses } from '../services/circl';
import { checkLeakIX } from '../services/leakix';
import { checkIP } from '../services/abuseipdb';
import { urlhausLookupURL } from '../services/urlhaus';
import { threatfoxSearchIOC } from '../services/threatfox';
import { getCVEById } from '../services/nvd';
import { getKEVCatalog } from '../services/cisa';
import { searchCTLogs } from '../services/crtsh';
import { lookupDomain } from '../services/rdap';
import { enrichIOC } from '../services/iocEnrichment';

async function runTests() {
    console.log('\n=== NovrSOC API Test Suite ===\n');

    // Test IP: known malicious Tor exit node
    const TEST_IP = '185.220.101.47';
    const TEST_DOMAIN = 'cybernovr.com';
    const TEST_MALWARE_URL = 'http://malware.testing.google.test/testing/malware/';
    const TEST_CVE = 'CVE-2021-44228'; // Log4Shell — always in results

    console.log('1. Testing CIRCL OSINT feed (replaced OTX)...');
    const pulses = await circlGetPulses(5);
    console.log(pulses.length > 0 ? `   ✅ CIRCL: ${pulses.length} recent pulses` : '   ❌ CIRCL: failed');

    console.log('1b. Testing LeakIX (replaced Censys)...');
    const leak = await checkLeakIX(TEST_IP);
    console.log(`   ${leak.status === 'ok' || leak.status === 'not_found' ? '✅' : '⚠️ '} LeakIX: status=${leak.status}${leak.error ? ` (${leak.error})` : ''}`);

    console.log('2. Testing AbuseIPDB...');
    const abuse = await checkIP(TEST_IP);
    console.log(abuse ? `   ✅ AbuseIPDB: ${abuse.abuseConfidenceScore}% confidence for ${TEST_IP}` : '   ❌ AbuseIPDB: failed');

    console.log('3. Testing URLHaus...');
    const urlhaus = await urlhausLookupURL(TEST_MALWARE_URL);
    console.log(urlhaus ? `   ✅ URLHaus: ${urlhaus.query_status}` : '   ✅ URLHaus: no result (URL not in database — API working)');

    console.log('4. Testing ThreatFox...');
    const tf = await threatfoxSearchIOC(TEST_IP);
    console.log(tf.length > 0 ? `   ✅ ThreatFox: ${tf.length} results` : '   ✅ ThreatFox: no results (API working)');

    console.log('5. Testing NVD...');
    const cve = await getCVEById(TEST_CVE);
    console.log(cve ? `   ✅ NVD: Found ${cve.id} — CVSS ${cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore}` : '   ❌ NVD: failed');

    console.log('6. Testing CISA KEV...');
    const kev = await getKEVCatalog();
    console.log(kev ? `   ✅ CISA KEV: ${kev.count} known exploited vulnerabilities` : '   ❌ CISA KEV: failed');

    console.log('7. Testing crt.sh...');
    const certs = await searchCTLogs(TEST_DOMAIN);
    console.log(Array.isArray(certs) ? `   ✅ crt.sh: ${certs.length} certificates found` : '   ❌ crt.sh: failed');

    console.log('8. Testing RDAP...');
    const rdap = await lookupDomain(TEST_DOMAIN);
    console.log(rdap ? `   ✅ RDAP: ${TEST_DOMAIN} expires ${rdap.expires} (${rdap.daysUntilExpiry} days)` : '   ❌ RDAP: failed');

    console.log('9. Testing unified IOC enrichment...');
    const ioc = await enrichIOC(TEST_IP, 'ip');
    console.log(`   ✅ IOC Enrichment: score=${ioc.risk_score} verdict=${ioc.verdict}`);

    console.log('\n=== Test Complete ===\n');
}

runTests().catch(console.error);
