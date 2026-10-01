import type { NormalizedEmailEvent, Provider } from '../eventModel';

export type ConnectionStatus = 'connected' | 'not_connected' | 'requires_configuration' | 'auth_error' | 'permission_error' | 'sync_error';

export interface Connection {
    id: string; org_id: string; provider: Provider; status: ConnectionStatus; tenant_id: string | null; tenant_name: string | null;
    admin_email: string | null; scopes: string[]; sync_cursor: string | null; last_sync: string | null; last_success_sync: string | null;
    last_event_at: string | null; last_error: string | null; connected_by: string | null; connected_at: string | null;
}

export interface SyncResult { events: NormalizedEmailEvent[]; cursor: string | null; fetched: number }

export interface Connector {
    provider: Provider;
    label: string;
    /** What the backend environment still needs before this connector can work at all. */
    missingConfig(): string[];
    /** The least-privilege permissions this connector asks for, shown to the admin before consent. */
    permissions: string[];
    /** Can we authenticate and read with the permissions granted? Throws the typed connector errors. */
    verify(conn: Connection): Promise<{ tenant_name: string | null; detail: string }>;
    /** Fetch new telemetry since conn.sync_cursor. */
    sync(conn: Connection): Promise<SyncResult>;
}
