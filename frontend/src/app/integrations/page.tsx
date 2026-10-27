import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Integrations | NovrSOC by Cybernovr',
    description: 'NovrSOC is built to sit on top of the security and IT stack you already run, not replace it. Verified connectors, supported protocols and open APIs — labelled exactly as they stand today.',
};

type IntegrationStatus = 'live' | 'protocol' | 'planned';
const STATUS_LABEL: Record<IntegrationStatus, string> = { live: 'Live', protocol: 'Protocol support', planned: 'Planned' };
const STATUS_STYLE: Record<IntegrationStatus, string> = {
    live: 'bg-green-100 text-green-700 border-green-200',
    protocol: 'bg-purple-100 text-purple-700 border-purple-200',
    planned: 'bg-gray-100 text-gray-500 border-gray-200',
};
function StatusPill({ s }: { s: IntegrationStatus }) {
    return <span className={`shrink-0 text-[9px] font-bold uppercase px-2 py-0.5 rounded-full border whitespace-nowrap ${STATUS_STYLE[s]}`}>{STATUS_LABEL[s]}</span>;
}

const CATEGORIES: { icon: string; title: string; desc: string; items: { label: string; status: IntegrationStatus }[] }[] = [
    {
        icon: '📊', title: 'SIEM & log management',
        desc: 'Correlate alongside, or in place of, an existing SIEM deployment.',
        items: [
            { label: 'Wazuh — native log/alert ingestion and real-time correlation', status: 'live' },
            { label: 'Generic alert-ingest API for any source that can POST in the expected shape', status: 'protocol' },
        ],
    },
    {
        icon: '🧱', title: 'Firewalls & network security',
        desc: 'Containment actions such as source-IP blocking route through your existing firewall.',
        items: [
            { label: 'OPNsense — syslog ingestion, tenancy-aware', status: 'live' },
            { label: 'Governed containment (block IP) executed through the connected firewall, gated by approval', status: 'live' },
        ],
    },
    {
        icon: '🖥️', title: 'Endpoint security / EDR',
        desc: 'Endpoint telemetry and behavioural detections feed the correlation layer.',
        items: [
            { label: 'Wazuh agents — endpoint telemetry and active response (isolate, etc.)', status: 'live' },
            { label: 'Dedicated connectors for other EDR/XDR vendors', status: 'planned' },
        ],
    },
    {
        icon: '🔍', title: 'Vulnerability scanners',
        desc: "NovrSOC's own scan engine runs the discovery and assessment work directly.",
        items: [
            { label: 'Native scan engine — nmap, Nuclei, Greenbone/OpenVAS', status: 'live' },
        ],
    },
    {
        icon: '🧬', title: 'Threat Intelligence feeds',
        desc: "Bring your own feeds into the platform alongside NovrSOC's own sources.",
        items: [
            { label: 'ThreatFox, URLhaus, Feodo Tracker (abuse.ch)', status: 'live' },
            { label: 'CISA Known Exploited Vulnerabilities catalogue', status: 'live' },
            { label: 'MISP — read-only connector, live once credentialed', status: 'live' },
            { label: 'TAXII 2.1 exchange — outbound sharing to credentialed partners', status: 'live' },
            { label: 'Bring your own feed into the correlation layer', status: 'protocol' },
        ],
    },
    {
        icon: '☁️', title: 'Cloud & identity',
        desc: 'Cloud posture and identity signals in the same correlated view.',
        items: [
            { label: 'Google sign-in', status: 'live' },
            { label: 'Cloud posture / workload scanning', status: 'planned' },
            { label: 'SAML-based SSO and multi-factor authentication', status: 'planned' },
        ],
    },
    {
        icon: '🎫', title: 'Ticketing / ITSM',
        desc: 'Cases and remediation tasks route into the workflow tools your teams already use.',
        items: [
            { label: 'Case and finding data available for ITSM workflows via the internal API surface', status: 'protocol' },
            { label: 'Prebuilt ITSM connectors', status: 'planned' },
        ],
    },
    {
        icon: '🏭', title: 'OT / ICS',
        desc: 'Passive, non-intrusive visibility designed for operational technology environments.',
        items: [
            { label: 'Authorised passive collection alongside IT (CNII Watch)', status: 'live' },
            { label: 'Active scanning of industrial control systems', status: 'planned' },
        ],
    },
];

const PROTOCOLS = [
    ['Syslog', 'OPNsense and other syslog-capable sources ship events to the platform for correlation.'],
    ['REST / webhook ingest', 'Wazuh and the alert-ingest path accept structured event data over HTTPS, authenticated with a scoped token.'],
    ['STIX 2.1 / TAXII 2.1', 'Threat intelligence is exported as STIX 2.1 objects and served over a standard TAXII 2.1 collection API.'],
    ['Scoped service credentials', 'Every external integration (scanning workers, SOAR actions, SIEM ingest) authenticates with its own token, not a shared one.'],
];

const ONBOARDING = [
    ['Read-only by default', 'A new data source starts as an observation-only feed into correlation; nothing acts on your environment until explicitly authorised.'],
    ['Scoped credentials, not shared ones', 'Each integration gets its own token or key, so revoking one connection never touches another.'],
    ['Tenant-isolated from day one', 'An integration is always connected to one organisation\'s data; it never becomes a shared, cross-tenant source by accident.'],
    ['Containment stays governed', 'Any action that changes something in your environment (blocking an IP, isolating a host) runs through the same approval workflow as a manually requested one.'],
];

export default function IntegrationsPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Integrations"
                eyebrow="NovrSOC / Integrations"
                title="Built to sit on top of what you run."
                description="NovrSOC is vendor-agnostic by design — it correlates and acts on data from the tools you already operate, rather than asking you to replace them."
            />

            <section className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="mb-10">
                        <h2 className="text-2xl font-black text-gray-900 mb-2">Verified connectors, by category</h2>
                        <p className="text-gray-500 max-w-2xl">
                            Every item below is labelled exactly as it stands today: a native, operational connector is
                            never shown the same way as a protocol we support for a bring-your-own source, or a
                            connector still on the roadmap.
                        </p>
                        <div className="flex flex-wrap gap-2 mt-4">
                            {(['live', 'protocol', 'planned'] as IntegrationStatus[]).map((s) => <StatusPill key={s} s={s} />)}
                        </div>
                    </div>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
                        {CATEGORIES.map((c) => (
                            <div key={c.title} className="bg-white border border-gray-100 rounded-2xl p-6">
                                <span className="text-3xl mb-3 block">{c.icon}</span>
                                <h3 className="font-black text-gray-900 mb-1.5">{c.title}</h3>
                                <p className="text-xs text-gray-400 leading-relaxed mb-4">{c.desc}</p>
                                <ul className="space-y-2">
                                    {c.items.map((it) => (
                                        <li key={it.label} className="flex items-start justify-between gap-2">
                                            <span className="text-xs text-gray-600 leading-snug">{it.label}</span>
                                            <StatusPill s={it.status} />
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-2">Architecture</h2>
                    <p className="text-gray-500 mb-6 leading-relaxed">
                        Every integration follows the same three-stage path: ingest, correlate, act. Data arrives from
                        your existing tools (Wazuh, OPNsense, threat feeds, the scan engine), is correlated against your
                        own assets, findings and cases, and only then can an action — always approval-gated — be
                        proposed back to one of those same tools.
                    </p>
                    <DetailItem title="Ingest">Each source writes into its own scoped table, keyed to your organisation — never a shared pool across tenants.</DetailItem>
                    <DetailItem title="Correlate">Indicators and findings are matched against your real inventory, open findings, alerts and cases — not evaluated in isolation.</DetailItem>
                    <DetailItem title="Act">A proposed response (such as blocking an address) is routed through the platform&apos;s approval workflow before it reaches the connected tool.</DetailItem>
                </div>
            </section>

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Supported protocols</h2>
                    {PROTOCOLS.map(([t, d]) => <DetailItem key={t} title={t}>{d}</DetailItem>)}
                </div>
            </section>

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Onboarding a new connection</h2>
                    {ONBOARDING.map(([t, d]) => <DetailItem key={t} title={t}>{d}</DetailItem>)}
                </div>
            </section>

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-2">API capabilities</h2>
                    <p className="text-gray-500 mb-6 leading-relaxed">
                        Today, two API surfaces are genuinely public; a broader self-serve developer API is planned,
                        not yet available.
                    </p>
                    <DetailItem title="Public scan endpoint — live">
                        An unauthenticated, rate-limited endpoint checks an IP, domain or URL against live threat
                        intelligence sources. It&apos;s the same endpoint the free scanner on the homepage calls directly.
                    </DetailItem>
                    <DetailItem title="TAXII 2.1 exchange — live">
                        Credentialed partners pull STIX 2.1 threat-intelligence objects over a standard TAXII 2.1
                        collection API, up to an agreed TLP ceiling.
                    </DetailItem>
                    <DetailItem title="Internal case, finding and alert APIs — in-platform">
                        Case, finding and alert data power the application itself and the ingest/response paths
                        described above. A general-purpose, self-serve public developer API over this data is planned.
                    </DetailItem>
                    <DetailItem title="Self-serve public developer API — planned">
                        Not yet publicly available. <Link href="/contact" className="text-purple font-semibold hover:underline">Contact us</Link> if
                        programmatic access to your own data is something you need now.
                    </DetailItem>
                </div>
            </section>

            <CTABand text="Ask us about connecting a specific tool in your stack." />
            <Footer />
        </div>
    );
}
