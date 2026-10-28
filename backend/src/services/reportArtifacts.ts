// R3.3E — artifact storage. Bytes live in Postgres (report_artifacts.bytes, BYTEA) rather than an
// object-storage bucket — see sql/2026-11-09_p30_report_scheduling.sql's header for why. PostgREST
// represents bytea as a hex string prefixed "\x" in both directions; encode/decode happens only
// here, so nothing else in the codebase needs to know that.

import { createHash, randomUUID } from 'crypto';
import { getSupabase } from './geoEnrichment';

export interface StoredArtifact { id: string; filename: string; content_type: string; bytes: Buffer; size_bytes: number; sha256: string; expires_at: string }

const toBytea = (b: Buffer): string => `\\x${b.toString('hex')}`;
const fromBytea = (hex: string): Buffer => Buffer.from(hex.startsWith('\\x') ? hex.slice(2) : hex, 'hex');

const CONTENT_TYPE: Record<'pdf' | 'csv', string> = { pdf: 'application/pdf', csv: 'text/csv; charset=utf-8' };
/** Artifact bytes are retained for a shorter window than the job/delivery audit trail — see the
 * migration's purge_expired_report_artifacts() vs purge_report_job_history(). */
const ARTIFACT_RETENTION_DAYS = 30;

export async function storeArtifact(reportJobId: string, format: 'pdf' | 'csv', filename: string, bytes: Buffer): Promise<{ id: string } | { error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'Database not configured' };
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const id = randomUUID();
    const expires_at = new Date(Date.now() + ARTIFACT_RETENTION_DAYS * 86_400_000).toISOString();
    const { error } = await supabase.from('report_artifacts').insert({
        id, report_job_id: reportJobId, format, filename, content_type: CONTENT_TYPE[format],
        bytes: toBytea(bytes), size_bytes: bytes.length, sha256, expires_at,
    });
    if (error) return { error: error.message };
    return { id };
}

/** The artifact for one job, newest first if more than one exists (there should only ever be one
 * per format per job). Returns null, never throws, when nothing is stored or it has expired and
 * been purged — the caller (routes/reports.ts) turns that into an honest 404, not a crash. */
export async function getArtifact(reportJobId: string, format?: 'pdf' | 'csv'): Promise<StoredArtifact | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    let q = supabase.from('report_artifacts').select('id, filename, content_type, bytes, size_bytes, sha256, expires_at').eq('report_job_id', reportJobId);
    if (format) q = q.eq('format', format);
    const { data, error } = await q.order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (error || !data) return null;
    return { ...data, bytes: fromBytea(data.bytes as unknown as string) } as StoredArtifact;
}
