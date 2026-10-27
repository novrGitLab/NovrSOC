// Synthetic demo data for the dedicated dev/test Supabase project — drives the real NovrSOC UI
// for Playwright capture. Entirely fictional: no real customer names, assets, or findings. Lives
// in video-production/ only, never committed into backend/. Idempotent-ish: safe to re-run (uses
// upsert / delete-then-insert for the rows it owns, keyed by the synthetic org slug).
import pg from 'pg';

const connectionString = process.env.PG_CONN_STRING;
if (!connectionString) { console.error('Set PG_CONN_STRING first.'); process.exit(1); }

const ORG_SLUG = 'demo-industries';
const client = new pg.Client({ connectionString, ssl: { rejectUnauthorized: false } });

const days = (n) => new Date(Date.now() + n * 86400000).toISOString();

async function main() {
  await client.connect();

  // 1. Organisation
  const orgRes = await client.query(
    `insert into organisations (slug, name, is_active, plan, industry, country, status, contact_name, contact_email, ciso_name, ciso_email, setup_complete)
     values ($1,$2,true,'enterprise','Financial Services','Nigeria','active','Ada Okafor','ada.okafor@demo-industries.example','Chidi Umeh','chidi.umeh@demo-industries.example',true)
     on conflict (slug) do update set name = excluded.name
     returning id`,
    [ORG_SLUG, 'Demo Industries Nigeria Ltd']
  );
  const orgId = orgRes.rows[0].id;
  console.log('org', orgId);

  // 2. Staff (platform_users) — org_id is the UUID here, unlike the text slug everywhere else.
  await client.query(`delete from platform_users where org_id = $1 and email like '%@demo-industries.example'`, [orgId]);
  // soc.manager is deliberately 'super_admin' (not the "SOC manager" the name implies) — it's the
  // account DEV_ADMIN_EMAIL (backend/.env) break-glass-matches, so sign-in resolves to THIS org
  // instead of the 'cybernovr' fallback in routes/auth.ts, and super_admin maximises what's
  // visible for capture.
  const staff = [
    ['soc.manager@demo-industries.example', 'Ngozi Adeyemi', 'super_admin'],
    ['analyst.one@demo-industries.example', 'Tunde Bakare', 'analyst'],
    ['analyst.two@demo-industries.example', 'Fatima Sule', 'analyst'],
  ];
  for (const [email, name, role] of staff) {
    await client.query(
      `insert into platform_users (org_id, email, name, role, status) values ($1,$2,$3,$4,'active')`,
      [orgId, email, name, role]
    );
  }

  // 3. VMS assets
  await client.query(`delete from vms_assets where org_id = $1`, [ORG_SLUG]);
  const assets = [
    ['domain', 'portal.demo-industries.example', 'internet', 'critical', ['portal.demo-industries.example'], ['41.203.68.10']],
    ['domain', 'mail.demo-industries.example', 'internet', 'high', ['mail.demo-industries.example'], ['41.203.68.11']],
    ['ip', '41.203.68.12', 'internet', 'high', [], ['41.203.68.12']],
    ['domain', 'vpn.demo-industries.example', 'internet', 'critical', ['vpn.demo-industries.example'], ['41.203.68.13']],
    ['host', 'DB-PRD-01', 'internal', 'critical', ['db-prd-01.corp.demo-industries.example'], ['10.20.0.11']],
    ['host', 'APP-PRD-02', 'internal', 'high', ['app-prd-02.corp.demo-industries.example'], ['10.20.0.22']],
    ['host', 'WIN-DC-01', 'internal', 'critical', ['win-dc-01.corp.demo-industries.example'], ['10.20.0.5']],
    ['domain', 'api.demo-industries.example', 'internet', 'medium', ['api.demo-industries.example'], ['41.203.68.14']],
  ];
  const assetIds = [];
  for (const [asset_type, value, exposure, criticality, hostnames, ips] of assets) {
    const r = await client.query(
      `insert into vms_assets (org_id, asset_type, value, exposure, criticality, hostnames, ips, alive, status)
       values ($1,$2,$3,$4,$5,$6,$7,true,'active') returning id`,
      [ORG_SLUG, asset_type, value, exposure, criticality, hostnames, ips]
    );
    assetIds.push(r.rows[0].id);
  }

  // 4. VMS findings — spread across severities, consistent with the real P1-P4 priority model.
  await client.query(`delete from vms_findings where org_id = $1`, [ORG_SLUG]);
  const sevPick = (i) => ['critical', 'critical', 'high', 'high', 'high', 'medium', 'medium', 'medium', 'low', 'low', 'low', 'info', 'info', 'critical', 'high'][i % 15];
  const priFor = { critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', info: 'P4' };
  const cveSample = ['CVE-2026-31337', 'CVE-2026-20144', 'CVE-2025-55021', 'CVE-2025-48912', null];
  const findingTitles = [
    'Outdated TLS configuration permits weak cipher suites',
    'Unauthenticated remote code execution in VPN appliance firmware',
    'SQL injection in legacy reporting endpoint',
    'Exposed administrative login panel',
    'Missing security headers (CSP, HSTS)',
    'Self-signed certificate on internet-facing host',
    'Outdated OpenSSH version with known advisories',
    'Directory listing enabled on web server',
    'Weak password policy on domain controller',
    'Unpatched Windows Server missing October security rollup',
    'Informational: verbose server banner disclosure',
    'SMBv1 enabled on internal file server',
    'Database server reachable from internet-facing subnet',
    'Expired SSL certificate on customer portal',
    'Outdated jQuery library with known XSS advisories',
  ];
  for (let i = 0; i < 24; i++) {
    const severity = sevPick(i);
    const assetId = assetIds[i % assetIds.length];
    const title = findingTitles[i % findingTitles.length];
    const cve = cveSample[i % cveSample.length];
    const riskScore = { critical: 92, high: 74, medium: 48, low: 22, info: 8 }[severity] - (i % 5);
    const status = i % 7 === 0 ? 'verified' : i % 11 === 0 ? 'risk_accepted' : 'open';
    await client.query(
      `insert into vms_findings (org_id, dedupe_key, asset_id, asset_value, source_class, detected_by, rule_id, title, description, finding_type, cve_ids, scanner_severity, scanner_cvss, risk_score, priority, status, first_seen, last_seen)
       values ($1,$2,$3,(select value from vms_assets where id = $3),'active_scan',$4,$5,$6,$7,'vulnerability',$8,$9,$10,$11,$12,$13,$14,$15)`,
      [
        ORG_SLUG, `demo-finding-${i}`, assetId, ['nuclei'], `rule-${1000 + i}`, title,
        'Synthetic demonstration finding for the NovrSOC conference video — not a real vulnerability.',
        cve ? [cve] : [], severity, severity === 'critical' ? 9.1 : severity === 'high' ? 7.4 : severity === 'medium' ? 5.3 : 2.1,
        riskScore, priFor[severity], status, days(-(20 - (i % 20))), days(-(i % 3)),
      ]
    );
  }

  // 5. Remediation tasks
  await client.query(`delete from vms_remediation_tasks where org_id = $1`, [ORG_SLUG]);
  const findingRows = (await client.query(`select id from vms_findings where org_id = $1 order by first_seen limit 6`, [ORG_SLUG])).rows;
  for (let i = 0; i < findingRows.length; i++) {
    await client.query(
      `insert into vms_remediation_tasks (org_id, finding_id, title, owner, due_at, status, created_by)
       values ($1,$2,$3,$4,$5,$6,'demo-seed')`,
      [ORG_SLUG, findingRows[i].id, `Remediate finding ${i + 1}`, 'analyst.one@demo-industries.example', days(i < 3 ? -2 : 5), i < 3 ? 'todo' : 'doing']
    );
  }

  // 6. Scan jobs
  await client.query(`delete from vms_scan_jobs where org_id = $1`, [ORG_SLUG]);
  const scopeRow = await client.query(`select id from vms_scopes where org_id = $1 limit 1`, [ORG_SLUG]);
  const scopeId = scopeRow.rows[0]?.id ?? null;
  if (scopeId) {
    await client.query(
      `insert into vms_scan_jobs (org_id, scope_id, kind, targets, status, requested_by, started_at, finished_at)
       values ($1,$2,'vuln_nuclei','["portal.demo-industries.example"]'::jsonb,'succeeded','analyst.one@demo-industries.example',$3,$4)`,
      [ORG_SLUG, scopeId, days(-1), days(-1)]
    );
    await client.query(
      `insert into vms_scan_jobs (org_id, scope_id, kind, targets, status, requested_by)
       values ($1,$2,'discovery','["vpn.demo-industries.example"]'::jsonb,'running','analyst.two@demo-industries.example')`,
      [ORG_SLUG, scopeId]
    );
  }

  // 7. Alerts
  await client.query(`delete from alerts where org_id = $1`, [ORG_SLUG]);
  const alertSevs = ['critical', 'high', 'high', 'medium', 'medium', 'low', 'critical', 'medium', 'low', 'high'];
  const alertRuleDesc = [
    'Multiple failed SSH logins followed by success',
    'Possible lateral movement detected via SMB',
    'Outbound connection to known malicious IP',
    'Suspicious PowerShell execution',
    'Unusual volume of outbound DNS queries',
    'New local administrator account created',
    'Ransomware-like file encryption behaviour detected',
    'Port scan detected from internal host',
    'Login from unusual geographic location',
    'Privilege escalation attempt detected',
  ];
  for (let i = 0; i < alertRuleDesc.length; i++) {
    await client.query(
      `insert into alerts (org_id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_id, agent_name, severity, event_time, status)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        ORG_SLUG, `demo-alert-${i}`, `${5700 + i}`, alertSevs[i] === 'critical' ? 15 : alertSevs[i] === 'high' ? 12 : alertSevs[i] === 'medium' ? 8 : 5,
        alertRuleDesc[i], `agent-0${(i % 4) + 1}`, ['DB-PRD-01', 'APP-PRD-02', 'WIN-DC-01', 'VPN-GW-01'][i % 4],
        alertSevs[i], days(-(i % 5)), i % 4 === 0 ? 'new' : i % 4 === 1 ? 'triaged' : i % 4 === 2 ? 'escalated' : 'closed',
      ]
    );
  }

  // 8. Cases
  await client.query(`delete from cases where org_id = $1`, [ORG_SLUG]);
  const caseDefs = [
    ['Suspected ransomware activity on DB-PRD-01', 'critical', 'investigating'],
    ['Phishing email reported by finance team', 'high', 'open'],
    ['Brute-force attempts against VPN gateway', 'high', 'contained'],
    ['Unusual admin account creation on domain controller', 'medium', 'resolved'],
    ['Outbound traffic to known-bad IP from APP-PRD-02', 'medium', 'open'],
  ];
  const caseIds = [];
  for (let i = 0; i < caseDefs.length; i++) {
    const [title, severity, status] = caseDefs[i];
    const r = await client.query(
      `insert into cases (org_id, title, description, severity, status, source, assigned_to, tier, created_at)
       values ($1,$2,$3,$4,$5,'wazuh','analyst.one@demo-industries.example',$6,$7) returning id`,
      [ORG_SLUG, title, 'Synthetic demonstration case for the NovrSOC conference video.', severity, status,
        severity === 'critical' ? 3 : severity === 'high' ? 2 : 1, days(-(i + 1))]
    );
    caseIds.push(r.rows[0].id);
  }

  // 9. Playbooks
  await client.query(`delete from playbooks where org_id = $1`, [ORG_SLUG]);
  await client.query(
    `insert into playbooks (org_id, name, severity, description, steps, estimated_time, created_by)
     values ($1,'Phishing Response','medium','Contain and investigate a reported phishing email.','["Quarantine message","Identify recipients","Reset affected credentials","Notify affected users"]'::jsonb,'45 min','soc.manager@demo-industries.example')`,
    [ORG_SLUG]
  );
  await client.query(
    `insert into playbooks (org_id, name, severity, description, steps, estimated_time, created_by)
     values ($1,'Ransomware Containment','critical','Isolate affected host and begin recovery.','["Isolate host","Preserve evidence","Notify executive stakeholders","Begin recovery from backup"]'::jsonb,'2-4 hrs','soc.manager@demo-industries.example')`,
    [ORG_SLUG]
  );

  // 10. Response approvals — the real human-in-the-loop control (not the raw SOAR auto-action).
  await client.query(`delete from response_approvals where org_id = $1`, [ORG_SLUG]);
  await client.query(
    `insert into response_approvals (org_id, action, target, target_label, reason, case_id, source, status, requested_by)
     values ($1,'isolate_agent','agent-01','DB-PRD-01','Suspected ransomware activity — isolate pending investigation',$2,'analyst','pending','analyst.one@demo-industries.example')`,
    [ORG_SLUG, caseIds[0]]
  );
  await client.query(
    `insert into response_approvals (org_id, action, target, target_label, reason, case_id, source, status, requested_by, decided_by, decided_at, result)
     values ($1,'block_ip','185.220.101.42','185.220.101.42','Known-bad IP observed contacting APP-PRD-02',$2,'analyst','approved','analyst.two@demo-industries.example','soc.manager@demo-industries.example',$3,'executed')`,
    [ORG_SLUG, caseIds[4], days(-1)]
  );

  // 11. Threat Intelligence — the real feed catalog (cisa_kev, feodo, misp, misp_events, opencti,
  // threatfox, urlhaus) is already seeded by backend/sql/2026-10-30_p25_ti_v1.sql itself; we only
  // refresh their status/counts so the Sources page shows them as recently, successfully run,
  // instead of adding fake duplicate rows under different ids.
  await client.query(
    `update ti_feeds set enabled = true, last_run_at = now(), last_success_at = now(),
     last_counts = jsonb_build_object('fetched', 140, 'new', 5, 'duplicates', 120)`
  );
  await client.query(`delete from ti_indicators where tags @> array['demo']`);
  const iocTypes = ['ip', 'domain', 'sha256', 'url'];
  for (let i = 0; i < 10; i++) {
    await client.query(
      `insert into ti_indicators (type, value, status, max_confidence, tags, malware_families, threat_types, source_count)
       values ($1,$2,'active',$3,array['demo'],$4,array['malware'],$5)`,
      [iocTypes[i % 4], `demo-ioc-${i}.example`, 60 + (i % 4) * 10, i % 3 === 0 ? ['Emotet'] : [], 2 + (i % 3)]
    );
  }

  // 12. CNII
  await client.query(`delete from cnii_org_profiles where org_id = $1`, [ORG_SLUG]);
  await client.query(
    `insert into cnii_org_profiles (org_id, sector_id, subfield, designation, created_by, updated_by)
     values ($1,'finance','Inter-Bank Payment Systems','designated','demo-seed','demo-seed')`,
    [ORG_SLUG]
  );
  await client.query(`delete from cnii_assets where org = $1`, [ORG_SLUG]);
  for (let i = 0; i < 4; i++) {
    await client.query(
      `insert into cnii_assets (ip, hostname, org, sector_id, risk_score, vuln_count, alert_count, scan_status)
       values ($1,$2,$3,'finance',$4,$5,$6,'completed')`,
      [`41.203.68.${20 + i}`, `cnii-host-${i}.demo-industries.example`, ORG_SLUG, 30 + i * 15, 2 + i, i]
    );
  }

  // 13. Email Security
  await client.query(`delete from email_domains where org_id = $1`, [ORG_SLUG]);
  await client.query(
    `insert into email_domains (org_id, domain, status, dmarc_policy, spf_status, dkim_status, dmarc_status, health_score, sending_sources)
     values ($1,'demo-industries.example','verified','reject','pass','pass','pass',96,2)`,
    [ORG_SLUG]
  );
  await client.query(`delete from dmarc_records where org_id = $1`, [ORG_SLUG]);
  await client.query(`delete from dmarc_aggregate_reports where org_id = $1`, [ORG_SLUG]);
  for (let i = 0; i < 5; i++) {
    const rep = await client.query(
      `insert into dmarc_aggregate_reports (org_id, domain, report_id, reporter, date_begin, date_end, record_count, message_count, pass_count, received_via)
       values ($1,'demo-industries.example',$2,'google.com',$3,$4,1,$5,$6,'email') returning id`,
      [ORG_SLUG, `demo-report-${i}`, days(-i - 1), days(-i), 40 + i * 12, i === 2 ? 0 : 40 + i * 12]
    );
    await client.query(
      `insert into dmarc_records (org_id, report_id, domain, source_ip, message_count, disposition, dmarc_pass, date_begin)
       values ($1,$2,'demo-industries.example',$3,$4,$5,$6,$7)`,
      [ORG_SLUG, rep.rows[0].id, `196.1.${i}.10`, 40 + i * 12, i === 2 ? 'quarantine' : 'none', i !== 2, days(-i)]
    );
  }
  await client.query(`delete from messaging_connections where org_id = $1`, [ORG_SLUG]);
  await client.query(
    `insert into messaging_connections (org_id, provider, status, tenant_name, connected_by, connected_at)
     values ($1,'microsoft365','connected','Demo Industries Nigeria Ltd','soc.manager@demo-industries.example',$2)`,
    [ORG_SLUG, days(-30)]
  );
  await client.query(`delete from phishing_domains where org_id = $1`, [ORG_SLUG]);
  await client.query(
    `insert into phishing_domains (org_id, domain, brand_domain, techniques, discovered_via, status, risk, risk_score)
     values ($1,'demo-industries-secure.example','demo-industries.example',array['typosquat'],'dark_web_monitor','discovered','medium',55)`,
    [ORG_SLUG]
  );

  console.log('Seed complete.');
  await client.end();
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
