// Attachment intelligence. Works on METADATA only — hash, name, declared type, size — as
// supplied by the mail provider or gateway. Files are never downloaded to, opened on, or
// executed on this server.
//
// Detonation belongs in an isolated sandbox. The SandboxProvider interface below is where one
// plugs in; the only implementation today is a hash lookup against a CAPE-compatible sandbox's
// REST API (SANDBOX_URL + SANDBOX_TOKEN). With no sandbox configured every result says
// "Sandbox unavailable" — never "clean".
import { threatfoxSearchIOC } from '../threatfox';
import { vtCheckHash, isConfigured as vtConfigured } from '../virustotal';

export interface AttachmentMeta { filename: string | null; sha256: string | null; size: number | null; content_type: string | null }

export interface SandboxReport { status: 'unavailable' | 'not_found' | 'reported' | 'error'; detail: string; score?: number; report_url?: string }
export interface SandboxProvider { name: string; configured(): boolean; lookup(sha256: string): Promise<SandboxReport> }

// CAPE Sandbox (open source, self-hosted): GET /apiv2/tasks/search/sha256/<hash>/
const capeSandbox: SandboxProvider = {
    name: 'CAPE',
    configured: () => !!process.env.SANDBOX_URL,
    async lookup(sha256) {
        const base = (process.env.SANDBOX_URL ?? '').replace(/\/$/, '');
        try {
            const r = await fetch(`${base}/apiv2/tasks/search/sha256/${sha256}/`, {
                headers: process.env.SANDBOX_TOKEN ? { Authorization: `Token ${process.env.SANDBOX_TOKEN}` } : {},
                signal: AbortSignal.timeout(8000),
            });
            if (!r.ok) return { status: 'error', detail: `Sandbox answered HTTP ${r.status}` };
            const d = (await r.json()) as { data?: { id: number; malscore?: number }[] };
            const task = d.data?.[0];
            if (!task) return { status: 'not_found', detail: 'The sandbox has not analysed this file.' };
            return { status: 'reported', detail: `Sandbox task ${task.id}`, score: task.malscore, report_url: `${base}/analysis/${task.id}/` };
        } catch (err) {
            return { status: 'error', detail: `Sandbox unreachable: ${(err as Error).message}` };
        }
    },
};
export function sandbox(): SandboxProvider { return capeSandbox; }

const EXECUTABLE = new Set(['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta', 'msi', 'dll', 'jar', 'lnk', 'reg', 'cpl']);
const CONTAINER = new Set(['iso', 'img', 'vhd', 'vhdx', 'zip', 'rar', '7z', 'gz', 'tar', 'cab', 'ace']);
const MACRO = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'xlsb']);
const HTML = new Set(['html', 'htm', 'shtml', 'svg', 'xhtml']);
const OTHER_RISKY = new Set(['one', 'chm', 'iqy', 'slk', 'xll', 'appref-ms', 'url']);

export interface AttachmentAnalysis extends AttachmentMeta {
    extension: string | null;
    file_class: 'executable' | 'macro_document' | 'container' | 'html' | 'risky_other' | 'document' | 'unknown';
    signals: string[];
    reputation: { source: string; consulted: boolean; malicious: boolean; detail: string }[];
    sandbox: SandboxReport;
    verdict: 'malicious' | 'suspicious' | 'no_known_threat';
}

export function classifyFile(filename: string | null): { extension: string | null; file_class: AttachmentAnalysis['file_class']; signals: string[] } {
    const name = (filename ?? '').toLowerCase();
    const parts = name.split('.');
    const ext = parts.length > 1 ? parts.pop()! : null;
    const signals: string[] = [];
    if (parts.length > 1 && ext && (EXECUTABLE.has(ext) || HTML.has(ext))) signals.push(`Double extension ("${filename}") hides the real file type.`);
    if (/[‮‎‏]/.test(filename ?? '')) signals.push('Right-to-left override character disguises the extension.');
    let cls: AttachmentAnalysis['file_class'] = 'unknown';
    if (ext && EXECUTABLE.has(ext)) { cls = 'executable'; signals.push(`.${ext} files run code when opened.`); }
    else if (ext && MACRO.has(ext)) { cls = 'macro_document'; signals.push(`.${ext} documents can carry macros.`); }
    else if (ext && CONTAINER.has(ext)) { cls = 'container'; signals.push(`.${ext} archives/disk images are used to smuggle payloads past filters.`); }
    else if (ext && HTML.has(ext)) { cls = 'html'; signals.push(`.${ext} attachments are a common credential-phishing delivery method.`); }
    else if (ext && OTHER_RISKY.has(ext)) { cls = 'risky_other'; signals.push(`.${ext} files are abused to deliver malware.`); }
    else if (ext) cls = 'document';
    return { extension: ext, file_class: cls, signals };
}

export async function analyzeAttachment(meta: AttachmentMeta): Promise<AttachmentAnalysis> {
    const { extension, file_class, signals } = classifyFile(meta.filename);
    const reputation: AttachmentAnalysis['reputation'] = [];
    const sha = meta.sha256 && /^[a-f0-9]{64}$/i.test(meta.sha256) ? meta.sha256.toLowerCase() : null;
    let sandboxReport: SandboxReport = { status: 'unavailable', detail: 'Sandbox unavailable — no sandbox is connected (SANDBOX_URL).' };

    if (sha) {
        const [tf, vt, sb] = await Promise.allSettled([
            threatfoxSearchIOC(sha),
            vtConfigured() ? vtCheckHash(sha) : Promise.resolve(null),
            sandbox().configured() ? sandbox().lookup(sha) : Promise.resolve(null),
        ]);
        const tfHits = tf.status === 'fulfilled' ? tf.value : [];
        reputation.push({ source: 'ThreatFox', consulted: tf.status === 'fulfilled', malicious: tfHits.length > 0, detail: tfHits.length ? `Known ${tfHits[0].malware_printable} sample` : 'Not listed' });
        if (!vtConfigured()) reputation.push({ source: 'VirusTotal', consulted: false, malicious: false, detail: 'Not configured (VIRUSTOTAL_API_KEY)' });
        else {
            const v = vt.status === 'fulfilled' ? vt.value : null;
            const mal = v?.stats?.malicious ?? 0;
            reputation.push({ source: 'VirusTotal', consulted: v !== null, malicious: mal >= 2, detail: v ? `${mal} engines flag it malicious` : 'Hash not known to VirusTotal' });
        }
        if (sb.status === 'fulfilled' && sb.value) sandboxReport = sb.value;
    } else {
        signals.push('No SHA-256 hash was supplied, so reputation could not be checked.');
    }

    const malicious = reputation.some((r) => r.malicious) || (sandboxReport.score ?? 0) >= 7;
    const suspicious = file_class === 'executable' || signals.some((s) => /Double extension|Right-to-left/.test(s));
    return { ...meta, sha256: sha, extension, file_class, signals, reputation, sandbox: sandboxReport, verdict: malicious ? 'malicious' : suspicious ? 'suspicious' : 'no_known_threat' };
}
