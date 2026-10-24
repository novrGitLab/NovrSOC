import { AlertQueue } from '@/components/features/AlertQueue';

// The client portal's read-only view of its own organisation's alerts and firewall activity
// (GET /api/client/secops/*). Replaces the staff Threat Management console, whose API is
// SecOps-only and always answered 403 here.
export default function Page() {
    return <AlertQueue mode="client" />;
}
