// R3.3E — server-side PDF generation for scheduled/downloaded reports.
//
// Every existing report page (VmsReport, CniiReport, TiReport) exports PDF today via
// frontend/src/components/shared/ExportButton.tsx, which uses html2canvas to screenshot a real
// rendered DOM element, then jsPDF to lay the image into a page. That approach needs an actual
// browser — it cannot run in a headless Node scheduler. New dependency: pdfkit (pure JavaScript,
// no Chromium/native binary, already in package.json). Justification for the dependency: the only
// realistic alternative that reuses the EXISTING html2canvas+jsPDF approach server-side is a
// headless browser (Puppeteer/Playwright), which would add a Chromium download to every backend
// build and deploy — a much heavier, slower-to-build dependency for the same outcome. pdfkit
// produces a different (simpler, text-based) visual layout than the browser-rendered reports;
// that tradeoff is accepted and stated here rather than hidden.

import PDFDocument from 'pdfkit';
import type { GeneratedReport } from './reportGeneration';

const PURPLE = '#520385';
const GREY = '#7A8099';
const INK = '#1C1F2E';

interface PdfSection { heading: string; lines: string[] }

const pairs = (o: Record<string, unknown> | undefined): string =>
    o && Object.keys(o).length ? Object.entries(o).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`).join('  ·  ') : 'none';

function vmsSections(d: Record<string, unknown>): PdfSection[] {
    const open = (d.open_now ?? {}) as Record<string, unknown>;
    const newIn = (d.new_in_period ?? {}) as Record<string, unknown>;
    const compliance = (d.compliance ?? {}) as { overall_impact?: string };
    return [
        { heading: 'Position now', lines: [
            `Open findings: ${open.total ?? 0}`,
            `By severity: ${pairs(open.by_severity as Record<string, unknown>)}`,
            `Overdue: ${open.overdue ?? 0}  ·  Known exploited (KEV): ${open.known_exploited ?? 0}  ·  Affected assets: ${open.affected_assets ?? 0}`,
        ] },
        { heading: 'In the period', lines: [
            `New findings: ${newIn.total ?? 0}`,
            `By priority: ${pairs(newIn.by_priority as Record<string, unknown>)}`,
        ] },
        { heading: 'Compliance context', lines: [
            `Overall impact: ${compliance.overall_impact ?? 'No impact'} — a technical mapping, not a compliance determination.`,
        ] },
    ];
}

function cniiSections(d: Record<string, unknown>): PdfSection[] {
    const stats = (d.stats ?? {}) as Record<string, unknown>;
    const open = (stats.open_findings ?? {}) as Record<string, unknown>;
    const ti = (d.threat_intelligence ?? {}) as Record<string, unknown>;
    const gaps = (d.gaps as string[] | undefined) ?? [];
    return [
        { heading: 'Coverage', lines: [
            `Coverage state: ${d.coverage_state ?? 'unknown'}`,
            `Assets: ${stats.assets ?? 0}  ·  Internet-facing: ${stats.internet_facing ?? 0}`,
            `Active authorised scopes: ${stats.active_scopes ?? 0}`,
        ] },
        { heading: 'Open exposure', lines: [
            `By priority: ${pairs(open)}`,
            `Known exploited (KEV) open: ${stats.kev_open ?? 0}`,
        ] },
        { heading: 'Threat intelligence', lines: [
            `${ti.total ?? 0} association(s) — ${ti.verified ?? 0} verified, ${ti.contextual ?? 0} contextual. A verified association is an analyst-promoted or case-linked match, never proof of compromise on its own.`,
        ] },
        { heading: 'Gaps to know before trusting these figures', lines: gaps.length ? gaps : ['None recorded.'] },
    ];
}

function tiSections(d: Record<string, unknown>): PdfSection[] {
    const matches = (d.matches ?? {}) as Record<string, unknown>;
    const relevant = (d.relevant ?? {}) as { by_tier?: Record<string, number>; top?: Record<string, unknown>[] };
    const kev = (d.kev ?? {}) as Record<string, unknown>;
    const top = relevant.top ?? [];
    return [
        { heading: 'Position now', lines: [
            `Active indicators: ${d.indicators_active ?? 0}`,
            `Current matches: ${matches.total ?? 0} (${pairs(matches.by_status as Record<string, unknown>)}) — ${matches.verified ?? 0} verified`,
            `Relevance: ${pairs(relevant.by_tier as unknown as Record<string, unknown>)}`,
        ] },
        { heading: 'Known exploited vulnerabilities', lines: [
            `New in period: ${kev.new_in_period ?? 0}  ·  Affecting your open findings: ${kev.your_open_findings ?? 0}`,
        ] },
        { heading: 'Top relevant matches', lines: top.length
            ? top.slice(0, 10).map((m) => `[${m.tier}] ${m.indicator_type}: ${m.indicator_value} — ${(m.reasons as string[] | undefined)?.join('; ') ?? ''}`)
            : ['None.'] },
    ];
}

function execSummarySections(d: Record<string, unknown>, warnings: string[]): PdfSection[] {
    const sections: PdfSection[] = [];
    if (d.vms) sections.push(...vmsSections(d.vms as Record<string, unknown>).map((s) => ({ ...s, heading: `Vulnerability Management — ${s.heading}` })));
    if (d.cnii) sections.push(...cniiSections(d.cnii as Record<string, unknown>).map((s) => ({ ...s, heading: `CNII Watch — ${s.heading}` })));
    if (d.threat_intel) sections.push(...tiSections(d.threat_intel as Record<string, unknown>).map((s) => ({ ...s, heading: `Threat Intelligence — ${s.heading}` })));
    if (d.secops) {
        const s = d.secops as Record<string, unknown>;
        sections.push({ heading: 'Security Operations', lines: [`Open cases: ${s.open_cases ?? 'n/a'}  ·  SLA rate: ${s.sla_rate ?? 'n/a'}  ·  Posture: ${s.posture ?? 'n/a'}`] });
    }
    if (warnings.length) sections.push({ heading: 'Not included in this summary', lines: warnings });
    return sections;
}

function sectionsFor(report: GeneratedReport): PdfSection[] {
    if (report.report_type === 'vms') return vmsSections(report.data);
    if (report.report_type === 'cnii') return cniiSections(report.data);
    if (report.report_type === 'threat_intel') return tiSections(report.data);
    return execSummarySections(report.data, report.warnings);
}

const REPORT_TITLE: Record<GeneratedReport['report_type'], string> = {
    vms: 'Vulnerability & Exposure Report', cnii: 'CNII Watch Report', threat_intel: 'Threat Intelligence Report', executive_summary: 'Unified Security Executive Summary',
};

/** Renders a GeneratedReport to a PDF buffer. Never throws on empty data — an organisation with
 * nothing to report still gets a real, honestly-empty document, not a crash. */
export function renderReportPdf(report: GeneratedReport): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ size: 'A4', margins: { top: 56, bottom: 56, left: 56, right: 56 } });
        const chunks: Buffer[] = [];
        doc.on('data', (c: Buffer) => chunks.push(c));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        doc.rect(0, 0, doc.page.width, 110).fill(PURPLE);
        doc.fillColor('#FFFFFF').fontSize(20).font('Helvetica-Bold').text(REPORT_TITLE[report.report_type], 56, 36);
        doc.fontSize(11).font('Helvetica').text(`${report.org_name}  ·  ${report.format === 'executive' ? 'Executive' : 'Technical'} view  ·  Last ${report.period_days} days`, 56, 68);

        doc.moveDown(4);
        doc.fillColor(GREY).fontSize(9).text(`Generated ${report.generated_at}  ·  All figures counted from stored platform records as of this generation.`);
        doc.moveDown(1);

        for (const section of sectionsFor(report)) {
            if (doc.y > doc.page.height - 120) doc.addPage();
            doc.fillColor(PURPLE).fontSize(13).font('Helvetica-Bold').text(section.heading);
            doc.moveDown(0.3);
            doc.fillColor(INK).fontSize(10).font('Helvetica');
            for (const line of section.lines) doc.text(`•  ${line}`, { indent: 10 });
            doc.moveDown(1);
        }

        if (report.warnings.length && report.report_type !== 'executive_summary') {
            if (doc.y > doc.page.height - 120) doc.addPage();
            doc.fillColor('#B45309').fontSize(12).font('Helvetica-Bold').text('Limitations');
            doc.fillColor(INK).fontSize(9).font('Helvetica');
            for (const w of report.warnings) doc.text(`•  ${w}`, { indent: 10 });
        }

        doc.end();
    });
}
