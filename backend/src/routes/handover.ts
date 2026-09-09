import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';

// SecOps shift handover log — now persisted to the Supabase `handover_logs` table.
//
// That table DOES exist (verified live against the real database on 2026-09-08; the previous
// comment here claiming it doesn't was stale). Its real columns are:
//   id uuid, org_id text NOT NULL, shift text, summary text, open_incidents jsonb,
//   pending_actions text[], escalations text[], submitted_by text, created_at timestamptz
//
// That shape is deliberately narrower than the handover this UI actually collects (which has
// two analyst names, a shift window, three alert counters, two incident lists, watch items and
// free-text notes — see frontend/src/components/features/ShiftHandover.tsx). Rather than drop
// the fields the table has no column for, the full log is written to `open_incidents` (jsonb,
// so it round-trips as a native object) and the columns that DO map are populated alongside it
// so the row is still readable/queryable in the Supabase table editor:
//   shift            <- "<start> → <end>"
//   summary          <- notes
//   pending_actions  <- ongoing incidents
//   escalations      <- critical incidents
//   submitted_by     <- the authenticated user's email
//
// GET rehydrates from the jsonb payload and falls back to the flat columns for any row written
// by something other than this route, so a hand-inserted row still renders.
//
// Supabase failures are never fatal: writes fall back to the in-process array this route used
// before, so a handover is never lost mid-shift just because the database is unreachable.

const router = Router();

interface HandoverLog {
    id: string;
    shift_start: string;
    shift_end: string;
    analyst_on: string;
    analyst_off: string;
    alerts_received: number;
    alerts_resolved: number;
    alerts_pending: number;
    critical_incidents: string[];
    ongoing_incidents: string[];
    watch_items: string;
    notes: string;
    submitted_at: string;
}

// Retained only as the fallback store for when Supabase is unconfigured or erroring — entries
// here still don't survive a restart, which is why the response flags `source` so the UI can
// say which one it got.
const memoryLogs: HandoverLog[] = [];

const DEFAULT_ORG_ID = 'cybernovr';

interface HandoverRow {
    id: string;
    org_id: string;
    shift: string | null;
    summary: string | null;
    open_incidents: unknown;
    pending_actions: string[] | null;
    escalations: string[] | null;
    submitted_by: string | null;
    created_at: string;
}

// Turn a stored row back into the shape ShiftHandover.tsx renders. The jsonb detail payload is
// authoritative when present; the flat columns cover rows written by anything else.
function rowToLog(row: HandoverRow): HandoverLog {
    const detail = (row.open_incidents && typeof row.open_incidents === 'object' && !Array.isArray(row.open_incidents)
        ? row.open_incidents
        : {}) as Partial<HandoverLog>;

    // `shift` is stored as "<start> → <end>" — split it back out for rows with no jsonb detail.
    const [shiftStart = '', shiftEnd = ''] = (row.shift ?? '').split('→').map((s) => s.trim());

    return {
        id: row.id,
        shift_start: detail.shift_start ?? shiftStart,
        shift_end: detail.shift_end ?? shiftEnd,
        analyst_on: detail.analyst_on ?? row.submitted_by ?? '',
        analyst_off: detail.analyst_off ?? '',
        alerts_received: detail.alerts_received ?? 0,
        alerts_resolved: detail.alerts_resolved ?? 0,
        alerts_pending: detail.alerts_pending ?? 0,
        critical_incidents: detail.critical_incidents ?? row.escalations ?? [],
        ongoing_incidents: detail.ongoing_incidents ?? row.pending_actions ?? [],
        watch_items: detail.watch_items ?? '',
        notes: detail.notes ?? row.summary ?? '',
        submitted_at: detail.submitted_at ?? row.created_at,
    };
}

router.get('/', async (req: AuthRequest, res) => {
    const orgId = req.user?.org_id || DEFAULT_ORG_ID;
    const supabase = getSupabase();

    if (supabase) {
        try {
            const { data, error } = await supabase
                .from('handover_logs')
                .select('*')
                .eq('org_id', orgId)
                .order('created_at', { ascending: false })
                .limit(20);
            if (error) throw error;
            res.json({ logs: (data ?? []).map((r) => rowToLog(r as HandoverRow)), source: 'supabase' });
            return;
        } catch (err) {
            console.warn('[Handover] Supabase read failed, serving in-memory logs:', err instanceof Error ? err.message : err);
        }
    }

    res.json({
        logs: [...memoryLogs].sort((a, b) => b.submitted_at.localeCompare(a.submitted_at)),
        source: 'memory',
    });
});

router.post('/', async (req: AuthRequest, res) => {
    const {
        shift_start, shift_end, analyst_on, analyst_off,
        alerts_received, alerts_resolved, alerts_pending,
        critical_incidents, ongoing_incidents, watch_items, notes,
    }: Partial<HandoverLog> = req.body ?? {};

    if (!analyst_on || !analyst_off || !shift_start || !shift_end) {
        res.status(400).json({ error: 'shift_start, shift_end, analyst_on, and analyst_off are required' });
        return;
    }

    const log: HandoverLog = {
        id: `HO-${Date.now()}`,
        shift_start, shift_end, analyst_on, analyst_off,
        alerts_received: alerts_received ?? 0,
        alerts_resolved: alerts_resolved ?? 0,
        alerts_pending: alerts_pending ?? 0,
        critical_incidents: critical_incidents ?? [],
        ongoing_incidents: ongoing_incidents ?? [],
        watch_items: watch_items ?? '',
        notes: notes ?? '',
        submitted_at: new Date().toISOString(),
    };

    const orgId = req.user?.org_id || DEFAULT_ORG_ID;
    const supabase = getSupabase();

    if (supabase) {
        try {
            const { data, error } = await supabase
                .from('handover_logs')
                .insert({
                    org_id: orgId,
                    shift: `${log.shift_start} → ${log.shift_end}`,
                    summary: log.notes,
                    // Full fidelity payload — every field the narrow column set can't hold.
                    open_incidents: { ...log, id: undefined },
                    pending_actions: log.ongoing_incidents,
                    escalations: log.critical_incidents,
                    submitted_by: req.user?.email || log.analyst_on,
                })
                .select()
                .single();
            if (error) throw error;

            res.json({ success: true, source: 'supabase', log: rowToLog(data as HandoverRow) });
            return;
        } catch (err) {
            // Never lose a handover to a database problem — fall through to the memory store and
            // tell the caller which one took it.
            const message = err instanceof Error ? err.message : String(err);
            console.error('[Handover] Supabase write failed, falling back to memory:', message);
            memoryLogs.push(log);
            res.json({ success: true, source: 'memory', warning: message, log });
            return;
        }
    }

    memoryLogs.push(log);
    res.json({ success: true, source: 'memory', log });
});

export default router;
