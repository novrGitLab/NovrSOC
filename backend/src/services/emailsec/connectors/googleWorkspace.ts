// Google Workspace connector — service account with domain-wide delegation, reading Gmail log
// events from the Admin SDK Reports API (applicationName=gmail).
//
// Least privilege: one read-only scope, admin.reports.audit.readonly — message metadata
// (sender, recipients, subject, spam/phish classification, authentication results, link
// domains). It does NOT use the Gmail API and never reads or copies anyone's mailbox.
//
// No secret is stored in the database: the service-account key lives in the backend
// environment (GOOGLE_WORKSPACE_SA_KEY), and the customer's Workspace admin authorises the
// service account's client id for the scope in their Admin console. Only the admin address to
// act as is recorded on the connection.
import { createSign } from 'crypto';
import { requestJson, ConnectorAuthError, ConnectorPermissionError } from './http';
import { fromGmailActivity, type GmailActivity } from '../eventModel';
import type { Connector, Connection, SyncResult } from './types';

export const GOOGLE_SCOPE = 'https://www.googleapis.com/auth/admin.reports.audit.readonly';
const REPORTS = 'https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/gmail';

interface ServiceAccount { client_email: string; private_key: string; token_uri?: string; client_id?: string }
export function serviceAccount(): ServiceAccount | null {
    const raw = process.env.GOOGLE_WORKSPACE_SA_KEY;
    if (!raw) return null;
    try {
        const json = raw.trim().startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
        const sa = JSON.parse(json) as ServiceAccount;
        return sa.client_email && sa.private_key ? sa : null;
    } catch { return null; }
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const tokens = new Map<string, { token: string; exp: number }>();

async function delegatedToken(adminEmail: string): Promise<string> {
    const sa = serviceAccount();
    if (!sa) throw new ConnectorAuthError('GOOGLE_WORKSPACE_SA_KEY is missing or not a service-account JSON key.');
    const cached = tokens.get(adminEmail);
    if (cached && cached.exp - 60_000 > Date.now()) return cached.token;
    const now = Math.floor(Date.now() / 1000);
    const aud = sa.token_uri ?? 'https://oauth2.googleapis.com/token';
    const unsigned = `${b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64url(JSON.stringify({ iss: sa.client_email, scope: GOOGLE_SCOPE, aud, sub: adminEmail, iat: now, exp: now + 3600 }))}`;
    const sig = createSign('RSA-SHA256').update(unsigned).sign(sa.private_key);
    try {
        const t = await requestJson<{ access_token: string; expires_in: number }>(aud, {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${b64url(sig)}` }),
        }, 'Google token', 1);
        tokens.set(adminEmail, { token: t.access_token, exp: Date.now() + t.expires_in * 1000 });
        return t.access_token;
    } catch (err) {
        const m = (err as Error).message;
        if (/unauthorized_client/i.test(m)) throw new ConnectorPermissionError(`Domain-wide delegation for ${GOOGLE_SCOPE} is not authorised for this service account in the Workspace Admin console.`);
        throw new ConnectorAuthError(m);
    }
}

export const googleWorkspace: Connector = {
    provider: 'google_workspace',
    label: 'Google Workspace',
    permissions: [`${GOOGLE_SCOPE} (domain-wide delegation) — Gmail log events, metadata only`],
    missingConfig: () => (serviceAccount() ? [] : ['GOOGLE_WORKSPACE_SA_KEY']),
    async verify(conn: Connection) {
        if (!conn.admin_email) throw new ConnectorAuthError('No Workspace admin address recorded.');
        const token = await delegatedToken(conn.admin_email);
        await requestJson(`${REPORTS}?maxResults=1`, { headers: { Authorization: `Bearer ${token}` } }, 'Google Reports API');
        return { tenant_name: conn.admin_email.split('@')[1] ?? null, detail: 'Delegated token issued and Gmail log events readable.' };
    },
    async sync(conn: Connection): Promise<SyncResult> {
        if (!conn.admin_email) throw new ConnectorAuthError('No Workspace admin address recorded.');
        const token = await delegatedToken(conn.admin_email);
        const since = conn.sync_cursor ?? new Date(Date.now() - 7 * 86_400_000).toISOString();
        const items: GmailActivity[] = [];
        let pageToken: string | undefined;
        for (let page = 0; page < 10; page++) {
            const p = new URLSearchParams({ startTime: since, maxResults: '500', ...(pageToken ? { pageToken } : {}) });
            const d = await requestJson<{ items?: GmailActivity[]; nextPageToken?: string }>(`${REPORTS}?${p}`, { headers: { Authorization: `Bearer ${token}` } }, 'Google Reports API');
            items.push(...(d.items ?? []));
            pageToken = d.nextPageToken;
            if (!pageToken) break;
        }
        const latest = items.map((i) => i.id?.time ?? '').sort().pop() || since;
        return { events: items.map(fromGmailActivity).filter((e): e is NonNullable<typeof e> => !!e), cursor: latest, fetched: items.length };
    },
};
