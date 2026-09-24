// How the platform recognises the OPNsense firewall among Wazuh agents: installed with the
// os-wazuh-agent plugin (see /admin/infra/opnsense-setup), it enrols as an ordinary agent. It is
// matched by name, or by its VPN address. Shared by Network Topology and the setup guide so both
// agree on whether the firewall is connected.

export interface WazuhAgentSummary {
    id: string;
    name: string;
    ip: string | null;
    status: string;
    lastSeen?: string | null;
    os?: string | null;
    group?: string;
}

// The firewall's address on the WireGuard link to the manager.
export const FIREWALL_VPN_IP = '10.0.0.4';

export function findFirewallAgent(agents: WazuhAgentSummary[]): WazuhAgentSummary | null {
    return agents.find((a) => a.name?.toLowerCase().includes('opnsense') || a.ip === FIREWALL_VPN_IP) ?? null;
}
