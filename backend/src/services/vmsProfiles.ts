// Scan profiles (phase P19). A profile is the set of scan steps an assessment plans for one target,
// with the port coverage of its port scan. Each profile says what it runs and what it does not
// cover, so nothing implies an engine or a check that is not there.
//
// Runnable as an assessment: discovery, standard, full. The catalogue also describes two coverage
// types that are not one-click scans here, with their real state:
//   authenticated  Wazuh's agent-side vulnerability detection (package inventory on the endpoint),
//                  synced hourly into findings. Greenbone credentialed checks are NOT available:
//                  NovrSOC stores no scan credentials.
//   verification   a focused rescan of one remediated finding (POST /findings/:id/verify).

import type { ProfileKind } from './vmsAssessments';

export const RUNNABLE_PROFILES = ['discovery', 'standard', 'full'] as const;
export type ProfileId = (typeof RUNNABLE_PROFILES)[number];
export const isProfileId = (v: unknown): v is ProfileId => typeof v === 'string' && (RUNNABLE_PROFILES as readonly string[]).includes(v);
/** The scope permission a profile needs before an endpoint is assessed with it. */
export const profileActivity = (p: ProfileId): 'ports' | 'vuln' => (p === 'discovery' ? 'ports' : 'vuln');

export interface ProfileDef {
    id: ProfileId;
    label: string;
    description: string;
    steps: readonly ProfileKind[];
    /** Port specification for the ports step (routes/vms.ts PORT_SPEC). */
    ports: string;
    engines: string[];
    not_covered: string[];
}

export const PROFILES: Record<ProfileId, ProfileDef> = {
    discovery: {
        id: 'discovery', label: 'Discovery',
        description: 'Finds what is there: live HTTP services, DNS and the 1,000 most common TCP ports with service and version detection.',
        steps: ['discovery', 'ports'], ports: 'top-1000',
        engines: ['httpx / dnsx / subfinder', 'Nmap (TCP connect, -sV)'],
        not_covered: ['No vulnerability checks', 'TCP ports outside the 1,000 most common', 'UDP'],
    },
    standard: {
        id: 'standard', label: 'Standard',
        description: 'Routine, production-safe assessment: discovery, the 1,000 most common TCP ports, and Nuclei templates (disruptive, fuzzing and brute-force templates excluded).',
        steps: ['discovery', 'ports', 'vuln_nuclei'], ports: 'top-1000',
        engines: ['httpx / dnsx / subfinder', 'Nmap (TCP connect, -sV)', 'Nuclei'],
        not_covered: ['Greenbone/OpenVAS network vulnerability tests', 'TCP ports outside the 1,000 most common', 'UDP', 'Authenticated (credentialed) checks'],
    },
    full: {
        id: 'full', label: 'Full Assessment',
        description: 'Comprehensive permitted coverage: discovery, every TCP port (1–65535) with version detection, Nuclei, and Greenbone/OpenVAS network vulnerability tests (safe checks only).',
        steps: ['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas'], ports: '1-65535',
        engines: ['httpx / dnsx / subfinder', 'Nmap (TCP connect, -sV)', 'Nuclei', 'Greenbone/OpenVAS'],
        not_covered: ['UDP', 'Authenticated (credentialed) checks', 'Checks that could disrupt a service (excluded on purpose)'],
    },
};

/** The catalogue as the API returns it, including the two coverage types that are not one-click scans. */
export function profileCatalogue(state: { wazuh_sync: { complete: boolean | null; last_complete_at: string | null } }) {
    return [
        ...RUNNABLE_PROFILES.map((id) => ({ ...PROFILES[id], runnable: true as const, available: null as boolean | null, availability_note: null as string | null })),
        {
            id: 'authenticated', label: 'Authenticated Assessment', runnable: false as const,
            description: 'Credential-level visibility of managed endpoints. NovrSOC gets it from the Wazuh agent on each endpoint: its package inventory is matched against vulnerability data and synced into findings every hour.',
            steps: [] as ProfileKind[], ports: '', engines: ['Wazuh vulnerability detection (agent-side)'],
            not_covered: ['Greenbone/OpenVAS credentialed checks: not available (NovrSOC stores no scan credentials)', 'Endpoints without a Wazuh agent'],
            available: state.wazuh_sync.last_complete_at !== null,
            availability_note: state.wazuh_sync.last_complete_at
                ? `Wazuh vulnerability data last synced completely at ${state.wazuh_sync.last_complete_at}${state.wazuh_sync.complete === false ? ' (the latest attempt was incomplete)' : ''}`
                : 'No complete Wazuh vulnerability sync yet',
        },
        {
            id: 'verification', label: 'Verification', runnable: false as const,
            description: 'A focused rescan of one finding after it is marked fixed: the same check on the same target (the Nuclei template that found it, or OpenVAS on the finding\'s port). Verified only if the rescan reached the target and no longer detects it.',
            steps: [] as ProfileKind[], ports: '', engines: ['Nuclei or Greenbone/OpenVAS, as originally detected'],
            not_covered: ['Wazuh findings: verified by the next Wazuh sync instead'],
            available: true, availability_note: 'Requested from a finding (Findings → Request verification)',
        },
    ];
}
