// Microsoft 365 onboarding: prove WHICH tenant the admin belongs to before connecting it.
//
// Microsoft's admin-consent callback carries a `tenant` query parameter that the browser can
// edit, and Microsoft's documentation says never to rely on it. With a multi-tenant app, any
// tenant that has consented to NovrSOC (for any customer) is readable with the app's credentials,
// so an edited tenant value could attach another customer's tenant. The flow is therefore:
//
//   1. Sign-in (OpenID Connect, scope "openid" only — no Graph permission is added). The admin
//      signs in; NovrSOC exchanges the code at the token endpoint (server to server, with the
//      client secret, over TLS) and validates the ID token: issuer, audience, expiry, nonce bound
//      to the signed state, and the tenant (tid) claim. Per OpenID Connect Core §3.1.3.7, TLS
//      validation of the token endpoint may replace checking the ID token signature when the
//      token comes directly from that endpoint, which it does here.
//   2. Admin consent is requested for THAT tenant only (/{tid}/v2.0/adminconsent), with the
//      verified tid inside a new signed state.
//   3. On the consent callback the browser-supplied `tenant` must equal the signed, verified tid;
//      the connection is stored with the verified tid, never the query value.
import jwt from 'jsonwebtoken';
import { requestJson } from './http';

export class M365IdentityError extends Error { constructor(m: string) { super(m); this.name = 'M365IdentityError'; } }

const LOGIN = 'https://login.microsoftonline.com';
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isTenantId = (v: unknown): v is string => typeof v === 'string' && GUID.test(v);

export function signInUrl(state: string, nonce: string): string {
    const p = new URLSearchParams({
        client_id: process.env.M365_CLIENT_ID ?? '', response_type: 'code', response_mode: 'query',
        redirect_uri: process.env.M365_REDIRECT_URI ?? '', scope: 'openid', state, nonce, prompt: 'select_account',
    });
    return `${LOGIN}/organizations/oauth2/v2.0/authorize?${p}`;
}

/** Admin consent for one specific, already-verified tenant. */
export function tenantConsentUrl(tenantId: string, state: string): string {
    if (!isTenantId(tenantId)) throw new M365IdentityError('Not a tenant id');
    const p = new URLSearchParams({ client_id: process.env.M365_CLIENT_ID ?? '', redirect_uri: process.env.M365_REDIRECT_URI ?? '', scope: 'https://graph.microsoft.com/.default', state });
    return `${LOGIN}/${tenantId}/v2.0/adminconsent?${p}`;
}

export interface VerifiedIdentity { tid: string; oid: string | null; username: string | null }

/** Validate an ID token's claims. `now` in seconds. Throws M365IdentityError with the reason. */
export function validateIdTokenClaims(idToken: string, expected: { clientId: string; nonce: string; now?: number }): VerifiedIdentity {
    const claims = jwt.decode(idToken) as Record<string, unknown> | null;
    if (!claims) throw new M365IdentityError('The ID token could not be read.');
    const now = expected.now ?? Math.floor(Date.now() / 1000);
    const tid = claims.tid;
    if (!isTenantId(tid)) throw new M365IdentityError('The ID token has no tenant (tid) claim.');
    if (claims.aud !== expected.clientId) throw new M365IdentityError('The ID token was issued to a different application.');
    if (claims.iss !== `${LOGIN}/${tid}/v2.0`) throw new M365IdentityError('The ID token issuer does not match its tenant.');
    if (typeof claims.exp !== 'number' || claims.exp < now - 60) throw new M365IdentityError('The ID token has expired.');
    if (typeof claims.nbf === 'number' && claims.nbf > now + 300) throw new M365IdentityError('The ID token is not valid yet.');
    if (!expected.nonce || claims.nonce !== expected.nonce) throw new M365IdentityError('The sign-in response does not match this connection attempt (nonce).');
    return { tid, oid: typeof claims.oid === 'string' ? claims.oid : null, username: typeof claims.preferred_username === 'string' ? claims.preferred_username : null };
}

/** Exchange the sign-in code at the token endpoint and return the validated identity. */
export async function redeemSignInCode(code: string, nonce: string): Promise<VerifiedIdentity> {
    const body = new URLSearchParams({
        client_id: process.env.M365_CLIENT_ID ?? '', client_secret: process.env.M365_CLIENT_SECRET ?? '', grant_type: 'authorization_code',
        code, redirect_uri: process.env.M365_REDIRECT_URI ?? '', scope: 'openid',
    });
    let t: { id_token?: string };
    try {
        t = await requestJson<{ id_token?: string }>(`${LOGIN}/organizations/oauth2/v2.0/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }, 'Microsoft sign-in', 1);
    } catch (err) {
        throw new M365IdentityError(`Microsoft sign-in could not be completed: ${(err as Error).message}`);
    }
    if (!t.id_token) throw new M365IdentityError('Microsoft returned no ID token.');
    return validateIdTokenClaims(t.id_token, { clientId: process.env.M365_CLIENT_ID ?? '', nonce });
}
