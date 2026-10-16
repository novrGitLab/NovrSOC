// Address classes for scanning decisions (phase P12). A scanner on the public internet cannot reach
// private, link-local, CGNAT or documentation addresses unless its operator declares a route to that
// network (the worker's VMS_WORKER_NETWORKS, recorded in vms_workers.networks). Mirrors the worker's
// `ipaddress.is_global` check (infra/vms-worker/worker.py target_route).

import { isIP } from 'net';
import { ipAllowed } from './cidr';

/** Not routable on the public internet. */
export const NON_PUBLIC_RANGES = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
    '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '240.0.0.0/4',
    '::1/128', 'fc00::/7', 'fe80::/10', '2001:db8::/32',
] as const;

/** True for an IP address that is not publicly routable; false for public addresses and non-IPs. */
export function isNonPublicIp(target: string): boolean {
    const t = target.trim().toLowerCase();
    return isIP(t) !== 0 && ipAllowed(t, NON_PUBLIC_RANGES);
}

/**
 * Whether a worker that declares `networks` has a path to `target`: any public address or hostname,
 * or a non-public address inside one of its networks. A CIDR target counts when its network address
 * is covered (scope entries are /22 or smaller).
 */
export function workerCanReach(target: string, networks: readonly string[]): boolean {
    const addr = target.includes('/') ? target.split('/')[0] : target;
    if (!isNonPublicIp(addr)) return true;
    return ipAllowed(addr.trim().toLowerCase(), networks);
}
