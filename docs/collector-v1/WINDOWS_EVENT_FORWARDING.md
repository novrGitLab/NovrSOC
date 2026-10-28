# Windows Event Forwarding → NovrSOC Collector V1

**This is a documented integration plan, not shipped code.** Nothing in `infra/novrsoc-collector/`
speaks Microsoft's native WEF subscription protocol, and nothing here claims it does — Vector has
no WEF source. A real Windows Event Collector (WEC) server does the WEF side; it then forwards
its own output into the Vector appliance as an ordinary syslog sender, the same as any firewall.

```
Windows source computers  --(WEF, source-initiated)-->  Windows Event Collector server
                                                               |
                                                   (an EventLog-to-syslog bridge)
                                                               v
                                             NovrSOC Collector V1 appliance (syslog_tcp/tls)
```

## 1. Prerequisites

- A Windows Server (2016+) designated as the WEC, with the **Windows Event Collector** service
  enabled (`wecutil qc`) and the **Windows Remote Management (WinRM)** service running
  (`winrm quickconfig`).
- Source computers (the machines whose events you want) reachable from the WEC over WinRM
  (TCP 5985 plain, or 5986 with HTTPS — use 5986 for anything beyond a lab).
- A domain, or at minimum Kerberos/NTLM auth between sources and the WEC. WEF without a domain
  (workgroup) is possible but needs per-host WinRM certificate configuration — out of scope here.

## 2. Source-initiated subscriptions (recommended over collector-initiated)

Source-initiated is the standard choice for anything beyond a handful of fixed machines: each
source computer polls the WEC's subscription list itself, so adding a new machine is a Group
Policy change, not a per-machine collector-side edit.

On the WEC:

```powershell
wecutil qc /q                     # enable the Event Collector service
wecutil cs subscription.xml       # create the subscription from a definition file
```

A minimal `subscription.xml` (forward Security, System and a chosen Application/Service log):

```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>NovrSOC-Security</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Security and System events for NovrSOC</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Normal</ConfigurationMode>
  <Query><![CDATA[
    <QueryList>
      <Query Id="0">
        <Select Path="Security">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
        <Select Path="System">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
      </Query>
    </QueryList>
  ]]></Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)(A;;GA;;;NS)S:</AllowedSourceDomainComputers>
</Subscription>
```

`AllowedSourceDomainComputers` above allows Domain Computers and Network Service — tighten this to
a specific security group in production (e.g. a "WEF-Forwarders" group), not every domain computer.

## 3. Group Policy requirements

On the source computers (via GPO, not per-machine):

- **Computer Configuration → Administrative Templates → Windows Components → Event Forwarding →
  Configure target Subscription Manager**: point at the WEC
  (`Server=http://<wec-host>:5985/wsman/SubscriptionManager/WEC,Refresh=60`).
- **Computer Configuration → Administrative Templates → Windows Components → Event Log Service →
  Security → Configure log access**: not required by default, but needed if Security-log access
  is restricted beyond the default `NT AUTHORITY\NETWORK SERVICE`.
- The **Network Service** account on each source computer needs "Manage auditing and security
  log" (via GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies →
  User Rights Assignment) to read the Security log for forwarding.
- WinRM listener GPO or `winrm quickconfig` on every source computer (or a GPO-deployed startup
  script doing the same) — WEF cannot start without it.

## 4. Validating ForwardedEvents

On the WEC, after a GPO refresh (`gpupdate /force` on a source, or wait for the policy cycle):

```powershell
wecutil gr NovrSOC-Security              # runtime status per source; "Active" per source computer
Get-WinEvent -LogName ForwardedEvents -MaxEvents 20
```

A source stuck at "Error" or absent from `wecutil gr` output usually means the Subscription
Manager GPO hasn't applied yet, or the source's WinRM listener isn't running — check
`winrm enumerate winrm/config/listener` on the source.

## 5. Bridging ForwardedEvents into the collector appliance

The WEC's own `ForwardedEvents` log needs to become syslog lines the Vector appliance's
`syslog_tcp`/`syslog_tls` source can receive. Two supported approaches — pick one per site, do not
run both against the same log:

- **NXLog Community Edition** on the WEC, reading `ForwardedEvents` via its `im_msvistalog` (or
  `im_etw`) input and writing `om_tcp`/`om_ssl` syslog output to this appliance's
  `SYSLOG_TCP_PORT`/`SYSLOG_TLS_PORT`. This is the most common, well-documented route and
  preserves the original computer name in the syslog message body (configure NXLog's output
  template to include `$SourceName`/`$Hostname`, not the WEC's own hostname — otherwise every
  event looks like it came from the collector server itself).
- **winlogbeat** with a `syslog`-shaped output template, if the site already standardises on the
  Elastic agent family for other reasons.

Either way: point the bridge at the WEC's `ForwardedEvents` log specifically (not each source's
local Security log — the WEC already consolidated those), and confirm the bridge's own syslog
payload still carries the **original** computer name and the **original** Windows Event ID in the
message text — both of these must survive the two hops (source → WEC → syslog bridge → Vector)
for NovrSOC's stored `collector_log_events.host` field to mean anything. Check this by comparing a
sample NovrSOC-received event's `host` and message against `Get-WinEvent` output for the same
event on the WEC before relying on it operationally.

## 6. Secure forwarding from the bridge into the appliance

Use the appliance's `syslog_tls` listener (`SYSLOG_TLS_PORT`, default 6515), not plain TCP/UDP,
for anything leaving the WEC's own network segment — Windows Security-log content is sensitive.
NXLog's `om_ssl` output and winlogbeat's TLS output both support this directly; point them at the
collector's certificate (`infra/novrsoc-collector/tls/collector.crt`) and set
`NOVRSOC_SYSLOG_TLS_VERIFY_CLIENT=false` unless you also issue the bridge its own client
certificate (most WEF-to-syslog bridges don't support presenting one).
