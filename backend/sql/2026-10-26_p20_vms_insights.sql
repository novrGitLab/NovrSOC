-- Phase P20 — VMS insights: risk and exposure history in the daily snapshot. Additive and
-- idempotent; needs P7 (vms_risk_snapshots). Changes no existing row.
--
-- The daily snapshot (services/vmsContinuous.ts snapshotOrg) also records, from that day on:
--   risk_mean           mean risk score (lib/riskScore.ts) of the open findings, informational excluded
--   risk_max            highest risk score among them
--   critical_exposures  open critical/high findings on internet-facing assets
--   open_by_severity    {"critical": n, "high": n, "medium": n, "low": n, "info": n}
-- Earlier days have no values: history is not reconstructed (the inputs of past days are gone), so
-- charts start from the first snapshot taken after this runs. The backend writes the snapshot
-- without these columns until this runs.

ALTER TABLE public.vms_risk_snapshots ADD COLUMN IF NOT EXISTS risk_mean NUMERIC(5,1);
ALTER TABLE public.vms_risk_snapshots ADD COLUMN IF NOT EXISTS risk_max INT;
ALTER TABLE public.vms_risk_snapshots ADD COLUMN IF NOT EXISTS critical_exposures INT;
ALTER TABLE public.vms_risk_snapshots ADD COLUMN IF NOT EXISTS open_by_severity JSONB;

NOTIFY pgrst, 'reload schema';

-- Rollback: none needed — the columns are nullable and earlier code ignores them. They hold
-- history worth keeping; do not drop them.
