// Microsoft 365 connector — Microsoft Entra ID admin consent + Microsoft Graph.
//
// Least privilege: the app asks for ONE application permission, SecurityAlert.Read.All, and
// reads Defender for Office 365 alerts (security/alerts_v2) with their message evidence —
// sender, recipient, subject, delivery action, URLs. It never requests Mail.Read, so NovrSOC
// cannot open anyone's mailbox; reading message content would be a separate, explicitly
// granted capability that this connector does not have.
//
// No secret is stored in the database. The app's client id / secret live in the backend
// environment; the customer's admin grants consent in their tenant and only the tenant id is
// recorded. Tokens are obtained with the client-credentials flow and cached in memory only.
import jwt from 'jsonwebtoken';
import { requestJson, ConnectorAuthError, ConnectorPermissionError } from './http';
import { fromMicrosoftAlert, type GraphAlert } from '../eventModel';
import type { Connector, Connection, SyncResult } from './types';

const GRAPH = 'https://graph.microsoft.com/v1.0';
export const M365_PERMISSIONS = ['SecurityAlert.Read.All (application) — Defender for Office 365 alerts and message metadata'];

export function m365Missing(): string[] {
    return ['M365_CLIENT_ID', 'M365_CLIENT_SECRET', 'M365_REDIRECT_URI'].filter((k) => !process.env[k]);
}

/** Admin-consent URL for a customer's Global Administrator to approve the app in their tenant. */
export function m365ConsentUrl(state: string): string {
    const p = new URLSearchParams({
        client_id: process.env.M365_CLIENT_ID ?? '',
        redirect_uri: process.env.M365_REDIRECT_URI ?? '',
        scope: 'https://graph.microsoft.com/.default',
        state,
    });
    return `https://login.microsoftonline.com/organizations/v2.0/adminconsent?${p}`;
}

const tokens = new Map<string, { token: string; exp: number }>();
async function appToken(tenantId: string): Promise<string> {
    const cached = tokens.get(tenantId);
    if (cached && cached.exp - 60_000 > Date.now()) return cached.token;
    const body = new URLSearchParams({
        client_id: process.env.M365_CLIENT_ID ?? '', client_secret: process.env.M365_CLIENT_SECRET ?? '',
        scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
    });
    const t = await requestJson<{ access_token: string; expires_in: number }>(
        `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
        { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }, 'Microsoft Entra token', 1,
    ).catch((err) => { throw new ConnectorAuthError(err.message.includes('AADSTS') ? err.message : `Microsoft Entra token: ${err.message}`); });
    tokens.set(tenantId, { token: t.access_token, exp: Date.now() + t.expires_in * 1000 });
    return t.access_token;
}

export const microsoft365: Connector = {
    provider: 'microsoft365',
    label: 'Microsoft 365',
    permissions: M365_PERMISSIONS,
    missingConfig: m365Missing,
    async verify(conn: Connection) {
        if (!conn.tenant_id) throw new ConnectorAuthError('No tenant recorded — run the admin consent step.');
        const token = await appToken(conn.tenant_id);
        const claims = jwt.decode(token) as { roles?: string[] } | null;
        if (!claims?.roles?.includes('SecurityAlert.Read.All')) {
            // Surface it as a permission problem rather than letting the first sync fail.
            throw new ConnectorPermissionError('Consent was given, but SecurityAlert.Read.All is not in the granted permissions. Add it to the app registration and re-consent.');
        }
        await requestJson(`${GRAPH}/security/alerts_v2?$top=1`, { headers: { Authorization: `Bearer ${token}` } }, 'Graph security alerts');
        return { tenant_name: null, detail: 'Token issued and Defender alerts readable.' };
    },
    async sync(conn: Connection): Promise<SyncResult> {
        if (!conn.tenant_id) throw new ConnectorAuthError('No tenant recorded — run the admin consent step.');
        const token = await appToken(conn.tenant_id);
        const since = conn.sync_cursor ?? new Date(Date.now() - 7 * 86_400_000).toISOString();
        const filter = `serviceSource eq 'microsoftDefenderForOffice365' and createdDateTime gt ${since}`;
        let url: string | null = `${GRAPH}/security/alerts_v2?$filter=${encodeURIComponent(filter)}&$top=50`;
        const alerts: GraphAlert[] = [];
        for (let page = 0; url && page < 10; page++) {
            const d: { value?: GraphAlert[]; '@odata.nextLink'?: string } = await requestJson(url, { headers: { Authorization: `Bearer ${token}` } }, 'Graph security alerts');
            alerts.push(...(d.value ?? []));
            url = d['@odata.nextLink'] ?? null;
        }
        const latest = alerts.map((a) => a.createdDateTime ?? '').sort().pop() || since;
        return { events: alerts.flatMap(fromMicrosoftAlert), cursor: latest, fetched: alerts.length };
    },
};
