// Content for the sensor setup guides (/admin/infra/opnsense-setup, sysmon-setup, osquery-setup).
//
// `{{MANAGER}}` in code is replaced with the Wazuh manager address from GET /api/wazuh/enrollment.
// Agent packages are pinned to the manager's version (4.14.7, read from the manager API on
// 2026-09-24) — a Wazuh agent must not be newer than its manager, or it is refused at enrolment.
// Bump this when the manager is upgraded.

import { findFirewallAgent, type WazuhAgentSummary } from './firewallAgent';

export type GuideId = 'opnsense' | 'sysmon' | 'osquery';

export interface GuideStep {
    title: string;
    body: string;
    code?: string;
    lang?: 'powershell' | 'bash' | 'xml' | 'json' | 'text';
}

export interface Guide {
    title: string;
    subtitle: string;
    intro: string;
    /** Agents this guide's sensor shows up as, for the live status panel. */
    matchAgents: (agents: WazuhAgentSummary[]) => WazuhAgentSummary[];
    matchLabel: string;
    /** What the status panel can and can't confirm. */
    statusNote: string;
    steps: GuideStep[];
}

export const WAZUH_AGENT_VERSION = '4.14.7-1';

const osIs = (a: WazuhAgentSummary, re: RegExp) => re.test(a.os ?? '');

export const GUIDES: Record<GuideId, Guide> = {
    opnsense: {
        title: 'OPNsense Setup',
        subtitle: 'Network · Connect the perimeter firewall',
        intro: 'OPNsense feeds Network Topology, Shadow IT and IP blocking. It enrols with the Wazuh manager as an agent through the os-wazuh-agent plugin, and NovrSOC blocks IPs through its API.',
        matchAgents: (agents) => {
            const fw = findFirewallAgent(agents);
            return fw ? [fw] : [];
        },
        matchLabel: 'OPNsense firewall agent',
        statusNote: 'Detected when an agent named "opnsense…" (or at 10.0.0.4) is registered with the manager.',
        steps: [
            {
                title: 'Install the Wazuh agent plugin',
                body: 'In the OPNsense web UI go to System → Firmware → Plugins, search for os-wazuh-agent and install it.',
            },
            {
                title: 'Point the agent at the manager',
                body: 'Services → Wazuh Agent → Settings: enable the agent, set the manager address below, and name the agent so NovrSOC recognises it as the firewall. Save and apply. The firewall must be able to reach the manager on TCP 1514 (events) and 1515 (enrolment).',
                code: 'Manager hostname:  {{MANAGER}}\nAgent name:        opnsense-fw',
                lang: 'text',
            },
            {
                title: 'Forward firewall and IDS logs',
                body: 'In the same plugin, enable forwarding of the firewall (filter) log. If Suricata runs on this box, go to Services → Intrusion Detection → Administration, enable IDS, select your rulesets (e.g. ET open), and tick "Enable eve syslog output" so its alerts reach the agent.',
            },
            {
                title: 'Create the block list NovrSOC writes to',
                body: 'Firewall → Aliases: add an alias named novrsoc_blocked of type Host(s), leave it empty, and apply. Then add a rule on the WAN interface that blocks source novrsoc_blocked, placed above your allow rules. The "Block IP" response action and the SOAR engine add attacker IPs to this alias.',
                code: 'Name:  novrsoc_blocked\nType:  Host(s)',
                lang: 'text',
            },
            {
                title: 'Create an API key for NovrSOC',
                body: 'System → Access → Users: create a dedicated user (e.g. novrsoc-api) with only the Firewall: Alias: Edit privilege, then press + under API keys. A key/secret file downloads. Set these on Railway (and in soar.env on the manager). The URL must be reachable from Railway; a private address such as 192.168.x.x is not.',
                code: 'OPNSENSE_URL=https://<firewall-public-address>\nOPNSENSE_KEY=<key from the file>\nOPNSENSE_SECRET=<secret from the file>\nOPNSENSE_ALIAS=novrsoc_blocked',
                lang: 'bash',
            },
            {
                title: 'Verify',
                body: 'Within a minute of the agent starting, the status panel above turns green and Network Topology switches to the connected view.',
            },
        ],
    },

    sysmon: {
        title: 'Windows (Sysmon)',
        subtitle: 'Network · Deep process and network telemetry from Windows endpoints',
        intro: 'Sysmon records process creation, network connections, driver loads and file changes in the Windows event log. The Wazuh agent forwards that channel, and the manager\'s built-in Sysmon rules turn it into alerts with MITRE mapping. Run each block in an elevated PowerShell.',
        matchAgents: (agents) => agents.filter((a) => osIs(a, /windows/i)),
        matchLabel: 'Windows agents',
        statusNote: 'Lists Windows agents registered with the manager. Whether Sysmon is forwarding is visible as Sysmon alerts on each asset\'s page — agent status alone can\'t confirm it.',
        steps: [
            {
                title: 'Install the Wazuh agent (skip if already installed)',
                body: 'Installs the agent, enrols it with the manager under the machine\'s name, and starts it.',
                code: `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-${WAZUH_AGENT_VERSION}.msi -OutFile $env:TEMP\\wazuh-agent.msi\nmsiexec.exe /i $env:TEMP\\wazuh-agent.msi /q WAZUH_MANAGER='{{MANAGER}}' WAZUH_AGENT_NAME=$env:COMPUTERNAME\nNET START WazuhSvc`,
                lang: 'powershell',
            },
            {
                title: 'Install Sysmon with a tuned configuration',
                body: 'Uses the widely used SwiftOnSecurity configuration, which filters out routine noise. Review it before deploying to production.',
                code: 'Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:TEMP\\Sysmon.zip\nExpand-Archive $env:TEMP\\Sysmon.zip -DestinationPath C:\\Sysmon -Force\nInvoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\\Sysmon\\sysmonconfig.xml\nC:\\Sysmon\\Sysmon64.exe -accepteula -i C:\\Sysmon\\sysmonconfig.xml',
                lang: 'powershell',
            },
            {
                title: 'Forward the Sysmon channel',
                body: 'Add this block inside <ossec_config> in C:\\Program Files (x86)\\ossec-agent\\ossec.conf, then restart the agent. (To roll it out to many machines, put it in the agent group\'s shared agent.conf on the manager instead.)',
                code: '<localfile>\n  <location>Microsoft-Windows-Sysmon/Operational</location>\n  <log_format>eventchannel</log_format>\n</localfile>',
                lang: 'xml',
            },
            {
                title: 'Restart and check',
                body: 'The second command should list recent Sysmon events. If it does, they are now reaching the manager.',
                code: 'Restart-Service -Name WazuhSvc\nGet-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5',
                lang: 'powershell',
            },
        ],
    },

    osquery: {
        title: 'Mac (osquery)',
        subtitle: 'Network · Scheduled system inventory from macOS endpoints',
        intro: 'osquery exposes the Mac as SQL tables — processes, listening ports, launch agents — and runs queries on a schedule. The Wazuh agent\'s osquery module collects the results. Run the commands in Terminal.',
        matchAgents: (agents) => agents.filter((a) => osIs(a, /mac ?os|darwin|os x/i)),
        matchLabel: 'macOS agents',
        statusNote: 'Lists macOS agents registered with the manager. Whether osquery results are arriving shows as osquery events on each asset\'s page — agent status alone can\'t confirm it.',
        steps: [
            {
                title: 'Install the Wazuh agent (skip if already installed)',
                body: 'Use arm64 on Apple silicon (M1 and later) and intel64 on Intel Macs.',
                code: `ARCH=$( [ "$(uname -m)" = "arm64" ] && echo arm64 || echo intel64 )\ncurl -so wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_AGENT_VERSION}.$ARCH.pkg"\necho "WAZUH_MANAGER='{{MANAGER}}'" > /tmp/wazuh_envs\nsudo installer -pkg ./wazuh-agent.pkg -target /\nsudo /Library/Ossec/bin/wazuh-control start`,
                lang: 'bash',
            },
            {
                title: 'Install osquery',
                body: 'Via Homebrew, or download the signed .pkg from osquery.io/downloads.',
                code: 'brew install --cask osquery',
                lang: 'bash',
            },
            {
                title: 'Configure the schedule',
                body: 'Save as /var/osquery/osquery.conf. Three starter queries: running processes, what is listening on the network, and persistence through launchd. Add more as needed.',
                code: JSON.stringify({
                    options: { logger_path: '/var/log/osquery', host_identifier: 'hostname', schedule_splay_percent: 10 },
                    schedule: {
                        processes: { query: 'SELECT pid, name, path, cmdline, uid FROM processes;', interval: 300 },
                        listening_ports: { query: 'SELECT lp.pid, lp.port, lp.protocol, lp.address, p.name, p.path FROM listening_ports lp JOIN processes p USING (pid);', interval: 300 },
                        launchd: { query: 'SELECT name, path, program, run_at_load FROM launchd;', interval: 3600 },
                    },
                }, null, 2),
                lang: 'json',
            },
            {
                title: 'Start osquery',
                code: 'sudo mkdir -p /var/log/osquery\nsudo osqueryctl start',
                body: 'Results are written to /var/log/osquery/osqueryd.results.log.',
                lang: 'bash',
            },
            {
                title: 'Enable the Wazuh osquery module',
                body: 'Add this inside <ossec_config> in /Library/Ossec/etc/ossec.conf, then restart the agent. run_daemon is "no" because osqueryd is already running on its own.',
                code: '<wodle name="osquery">\n  <disabled>no</disabled>\n  <run_daemon>no</run_daemon>\n  <log_path>/var/log/osquery/osqueryd.results.log</log_path>\n  <config_path>/var/osquery/osquery.conf</config_path>\n  <add_labels>yes</add_labels>\n</wodle>',
                lang: 'xml',
            },
            {
                title: 'Restart the agent',
                code: 'sudo /Library/Ossec/bin/wazuh-control restart',
                body: 'Scheduled query results start arriving at the manager within the first query interval (five minutes for the starter queries).',
                lang: 'bash',
            },
        ],
    },
};
