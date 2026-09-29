// NovrSOC mail gateway connector. The gateway (Postfix + Amavis on the mail host) already
// reports every scanned message to POST /api/email-proxy/verdict, which stores it in email_logs
// (services/emailProxy.ts). This connector turns those rows into normalised events.
//
// It only ever records what the gateway reported. email_logs holds a verdict, not the action
// the gateway took, so a phishing verdict is recorded as "flagged" unless the row says the
// message was rejected or held.
import { getSupabase } from '../../geoEnrichment';
import { ConnectorAuthError, ConnectorSyncError } from './http';
import { fromGateway, type GatewayLogRow } from '../eventModel';
import type { Connector, Connection, SyncResult } from './types';

export const gateway: Connector = {
    provider: 'gateway',
    label: 'NovrSOC Mail Gateway',
    permissions: ['Receives verdicts from the NovrSOC mail host (MX record pointed at the gateway). No mailbox access.'],
    missingConfig: () => (process.env.EMAIL_PROXY_TOKEN ? [] : ['EMAIL_PROXY_TOKEN']),
    async verify(conn: Connection) {
        if (!process.env.EMAIL_PROXY_TOKEN) throw new ConnectorAuthError('EMAIL_PROXY_TOKEN is not set, so the mail host cannot report verdicts.');
        const sb = getSupabase();
        if (!sb) throw new ConnectorSyncError('Database not configured.');
        const { data, error } = await sb.from('email_logs').select('received_at').eq('org_id', conn.org_id).order('received_at', { ascending: false }).limit(1);
        if (error) throw new ConnectorSyncError(`email_logs: ${error.message}`);
        const last = (data?.[0] as { received_at?: string } | undefined)?.received_at;
        return { tenant_name: null, detail: last ? `Last verdict received ${last}.` : 'Ready — no verdicts received yet. Point the domain MX at the gateway to start.' };
    },
    async sync(conn: Connection): Promise<SyncResult> {
        const sb = getSupabase();
        if (!sb) throw new ConnectorSyncError('Database not configured.');
        const since = conn.sync_cursor ?? new Date(Date.now() - 7 * 86_400_000).toISOString();
        const { data, error } = await sb.from('email_logs').select('*').eq('org_id', conn.org_id).gt('received_at', since).order('received_at', { ascending: true }).limit(500);
        if (error) throw new ConnectorSyncError(`email_logs: ${error.message}`);
        const rows = (data ?? []) as GatewayLogRow[];
        return { events: rows.map(fromGateway), cursor: rows.length ? rows[rows.length - 1].received_at ?? since : since, fetched: rows.length };
    },
};
