// Shared test fixtures (not a test file).
import { deflateRawSync, crc32 } from 'zlib';

/** Report window: two days ago, so it falls inside analytics / overview windows. */
export const REPORT_BEGIN = Math.floor(Date.now() / 1000) - 2 * 86_400;

export const SAMPLE_REPORT = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>${REPORT_BEGIN}</begin><end>${REPORT_BEGIN + 86_399}</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>120</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>example.com</domain><result>pass</result><selector>google</selector></dkim><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>203.0.113.9</source_ip><count>14</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from><envelope_from>bad.example</envelope_from></identifiers>
    <auth_results><spf><domain>bad.example</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`;

/** Minimal single-entry zip (deflate), as receivers like Microsoft send. */
export function zipOf(name: string, content: string): Buffer {
    const data = Buffer.from(content);
    const comp = deflateRawSync(data);
    const nameBuf = Buffer.from(name);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(comp.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc, 16); central.writeUInt32LE(comp.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(0, 42);
    const cdOffset = 30 + nameBuf.length + comp.length;
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10);
    end.writeUInt32LE(46 + nameBuf.length, 12); end.writeUInt32LE(cdOffset, 16);
    return Buffer.concat([local, nameBuf, comp, central, nameBuf, end]);
}
