// NovrSOC mail gateway connector. The gateway (Postfix + Amavis on the mail host) reports every
// scanned message to POST /api/email-proxy/verdict with the shared EMAIL_PROXY_TOKEN; that route
// stores it in email_logs under the organisation that registered the recipient's domain
// (services/emailProxy.ts). This connector turns those rows into normalised events.
//
// It only ever records what the gateway reported. email_logs holds a verdict, not the action
// the gateway took, so a phishing verdict is recorded as "flagged" unless the row says the
// message was rejected or held.
import { emailProxyStore } from '../../emailProxy';
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
        const { rows, error } = await emailProxyStore().logsSince(conn.org_id, new Date(Date.now() - 30 * 86_400_000).toISOString(), 1000);
        if (error) throw new ConnectorSyncError(`email_logs: ${error}`);
        const last = rows.map((r) => String(r.received_at ?? '')).sort().pop();
        return { tenant_name: null, detail: last ? `Last verdict received ${last}.` : 'Ready — no verdicts in the last 30 days. Point the domain MX at the gateway and register the domain.' };
    },
    async sync(conn: Connection): Promise<SyncResult> {
        const since = conn.sync_cursor ?? new Date(Date.now() - 7 * 86_400_000).toISOString();
        const { rows, error } = await emailProxyStore().logsSince(conn.org_id, since, 500);
        if (error) throw new ConnectorSyncError(`email_logs: ${error}`);
        const logs = rows as unknown as GatewayLogRow[];
        return { events: logs.map(fromGateway), cursor: logs.length ? logs[logs.length - 1].received_at ?? since : since, fetched: logs.length };
    },
};
