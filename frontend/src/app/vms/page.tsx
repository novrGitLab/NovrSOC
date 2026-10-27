import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Vulnerability Management | NovrSOC by Cybernovr',
    description: 'Discover, assess, prioritise and track findings with evidence, business context and continuous verification.',
};

export default function VMSPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Vulnerability Management"
                eyebrow="NovrSOC / Vulnerability Management"
                title="Turn vulnerabilities into a clear remediation plan."
                description="Discover, assess, prioritise and track findings with evidence, business context and continuous verification."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Built for clarity across the security lifecycle</h2>
                    <DetailItem title="Asset discovery">
                        Discover assets across internal infrastructure and your internet-facing footprint, kept continuously up to date.
                    </DetailItem>
                    <DetailItem title="Full-stack scanning">
                        Scan infrastructure, web applications, APIs, cloud configuration and containers from one platform.
                    </DetailItem>
                    <DetailItem title="Governed scan execution">
                        Scheduled, on-demand and unauthenticated scans, plus custom signatures, run within approved scopes and non-intrusive workflows.
                    </DetailItem>
                    <DetailItem title="CVE / NVD / CWE identification">
                        Findings are identified against CVE, NVD and CWE, not just a scanner&apos;s own naming.
                    </DetailItem>
                    <DetailItem title="Misconfiguration checks">
                        Checked against NIST, CIS, NDPA and NCS-CRF baselines, alongside known-CVE scanning.
                    </DetailItem>
                    <DetailItem title="Risk-based prioritisation">
                        Prioritise by CVSS v3/v4, CISA KEV status, exploit availability and asset criticality — not raw severity alone.
                    </DetailItem>
                    <DetailItem title="Remediation lifecycle">
                        Track owners, tasks, evidence, verification and overdue findings, rolled up into executive-ready reporting on risk reduction.
                    </DetailItem>
                    <DetailItem title="Compliance gap mapping">
                        Link vulnerability findings to NDPA, CBN, NCC, ISO/IEC 27001 and PCI-DSS controls, with evidence ready for auditors.
                    </DetailItem>
                </div>
            </section>

            <section id="tem" className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-4xl mx-auto px-6">
                    <div className="inline-flex items-center gap-2 bg-purple-100 border border-purple-200 rounded-full px-4 py-2 mb-6">
                        <span className="text-purple-700 text-xs font-bold">Threat Exposure Management</span>
                    </div>
                    <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-4">
                        From a single finding to a sector-wide exposure programme.
                    </h2>
                    <p className="text-gray-500 mb-8 leading-relaxed max-w-2xl">
                        TEM extends vulnerability management from a per-asset list into a continuously managed exposure
                        programme, across one organisation or an entire sector.
                    </p>
                    <div className="grid md:grid-cols-2 gap-4">
                        {[
                            ['Continuous exposure monitoring', 'Exposure is tracked continuously, not reassessed at the next scan window.'],
                            ['Sector heatmaps', 'Roll exposure up to a sector view, with drill-down to the organisation behind any hotspot.'],
                            ['Remediation workflows', 'Push remediation tasks into your own work-management system or ITSM tool over API.'],
                            ['Approval workflows & SLAs', 'Route remediation through approval where required, against defined remediation SLAs.'],
                        ].map(([title, desc]) => (
                            <div key={title} className="bg-white border border-gray-100 rounded-2xl p-5">
                                <h4 className="font-black text-gray-900 mb-1">{title}</h4>
                                <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            <RelatedLinks
                items={[
                    { href: '/cnii', title: 'CNII Watch', desc: 'See risk through a national, sector, subsector and organisation lens.' },
                    { href: '/ti', title: 'Threat Intelligence', desc: 'Correlate indicators, advisories and local intelligence with your environment.' },
                    { href: '/secops', title: 'Detection & Response', desc: 'Turn alerts into cases and governed response workflows, supported by AI.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
