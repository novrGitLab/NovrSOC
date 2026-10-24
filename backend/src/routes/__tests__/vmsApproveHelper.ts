// Test helper (phase P27): a scope entry that permits active scanning is created pending; tests that
// need an active scope approve it the way production does — the organisation's administrator
// (executive) reads the request's declaration and approves it through the API. Not a test file.

type Http = (method: string, path: string, bearer?: string, body?: unknown) => Promise<{ status: number; data: any }>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** If the creation answered "approval required", approve it as `executive`; returns the response with the now-active scope(s). */
export async function approveIfPending<T extends { status: number; data: any }>(http: Http, created: T, executive: string): Promise<T> { // eslint-disable-line @typescript-eslint/no-explicit-any
    if (created.status !== 201 || !created.data?.approval_required) return created;
    const group = created.data.request_group_id as string;
    const req = await http('GET', `/api/vms/scope-requests/${group}`, executive);
    if (req.status !== 200) throw new Error(`approveIfPending: request not readable (${req.status} ${JSON.stringify(req.data)})`);
    const a = await http('POST', `/api/vms/scope-requests/${group}/approve`, executive, {
        authority_name: 'Ada Obi', authority_title: 'Chief Information Security Officer', organisation_name: req.data.organisation_name,
        declaration_version: req.data.declaration_version, declaration_accepted: true,
    });
    if (a.status !== 200) throw new Error(`approveIfPending: approval refused (${a.status} ${JSON.stringify(a.data)})`);
    const scopes = a.data.scopes as { id: string }[];
    created.data = created.data.scope ? { ...created.data, scope: scopes.find((s) => s.id === created.data.scope.id) ?? scopes[0] } : { ...created.data, scopes };
    return created;
}
