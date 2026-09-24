'use client';

import { useState } from 'react';

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
    return (
        <button
            onClick={() => onChange(!value)}
            className={`relative w-9 h-5 rounded-full transition-colors flex-shrink-0 ${value ? 'bg-grey-100' : 'bg-card-muted'}`}
        >
            <span className={`absolute top-0.5 w-4 h-4 bg-card rounded-full shadow transition-transform ${value ? 'translate-x-4' : 'translate-x-0.5'}`} />
        </button>
    );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="h-[3px] bg-blue from-blue via-blue to-red-500" />
            <div className="p-5 space-y-4">
                <p className="text-xs font-bold text-foreground uppercase tracking-wide">{title}</p>
                {children}
                <div className="pt-2 border-t border-border">
                    <button className="px-4 py-2 bg-orange hover:bg-orange-hover text-white text-xs font-bold rounded-lg transition-colors">
                        Save Changes
                    </button>
                </div>
            </div>
        </div>
    );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div className="flex items-center justify-between gap-4">
            <span className="text-xs text-foreground-muted">{label}</span>
            {children}
        </div>
    );
}

export default function SettingsPage() {
    const [orgName, setOrgName]       = useState('Cybernovr');
    const [timezone, setTimezone]     = useState('Africa/Lagos (WAT)');
    const [dateFormat, setDateFormat] = useState('DD/MM/YYYY');
    const [currency, setCurrency]     = useState('Nigerian Naira (₦)');

    const [slaWarn, setSlaWarn]       = useState('30');
    const [maxOpen, setMaxOpen]       = useState('10');
    const [critEmail, setCritEmail]   = useState(true);

    const [emailNotifs, setEmailNotifs] = useState(true);
    const [smsAlerts,   setSmsAlerts]   = useState(false);

    const [alertRet,  setAlertRet]  = useState('90');
    const [logRet,    setLogRet]    = useState('365');
    const [reportRet, setReportRet] = useState('730');

    return (
            <div className="space-y-5">
                <div>
                    <h1 className="text-lg font-black text-foreground">Platform Settings</h1>
                    <p className="text-xs text-foreground-muted">Administration · Configure NovrSOC platform preferences</p>
                </div>

                <Section title="General Settings">
                    <Row label="Organisation Name">
                        <input value={orgName} onChange={e => setOrgName(e.target.value)}
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-56 focus:outline-none focus:ring-2 focus:ring-blue/20" />
                    </Row>
                    <Row label="Timezone">
                        <select value={timezone} onChange={e => setTimezone(e.target.value)}
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-56 focus:outline-none">
                            <option>Africa/Lagos (WAT)</option>
                            <option>UTC</option>
                            <option>Europe/London (GMT)</option>
                        </select>
                    </Row>
                    <Row label="Date Format">
                        <select value={dateFormat} onChange={e => setDateFormat(e.target.value)}
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-56 focus:outline-none">
                            <option>DD/MM/YYYY</option>
                            <option>MM/DD/YYYY</option>
                            <option>YYYY-MM-DD</option>
                        </select>
                    </Row>
                    <Row label="Currency">
                        <select value={currency} onChange={e => setCurrency(e.target.value)}
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-56 focus:outline-none">
                            <option>Nigerian Naira (₦)</option>
                            <option>US Dollar ($)</option>
                            <option>Euro (€)</option>
                        </select>
                    </Row>
                </Section>

                <Section title="Alert Thresholds">
                    <Row label="Critical alert email notifications">
                        <Toggle value={critEmail} onChange={setCritEmail} />
                    </Row>
                    <Row label="SLA breach warning (minutes)">
                        <input type="number" value={slaWarn} onChange={e => setSlaWarn(e.target.value)} min="1"
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-24 focus:outline-none focus:ring-2 focus:ring-blue/20" />
                    </Row>
                    <Row label="Max open incidents before escalation">
                        <input type="number" value={maxOpen} onChange={e => setMaxOpen(e.target.value)} min="1"
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-24 focus:outline-none focus:ring-2 focus:ring-blue/20" />
                    </Row>
                </Section>

                <Section title="Notification Settings">
                    <Row label="Email notifications">
                        <Toggle value={emailNotifs} onChange={setEmailNotifs} />
                    </Row>
                    <Row label="SMS alerts">
                        <Toggle value={smsAlerts} onChange={setSmsAlerts} />
                    </Row>
                </Section>

                <Section title="Data Retention">
                    <Row label="Alert retention (days)">
                        <input type="number" value={alertRet} onChange={e => setAlertRet(e.target.value)} min="1"
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-24 focus:outline-none focus:ring-2 focus:ring-blue/20" />
                    </Row>
                    <Row label="Log retention (days)">
                        <input type="number" value={logRet} onChange={e => setLogRet(e.target.value)} min="1"
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-24 focus:outline-none focus:ring-2 focus:ring-blue/20" />
                    </Row>
                    <Row label="Report retention (days)">
                        <input type="number" value={reportRet} onChange={e => setReportRet(e.target.value)} min="1"
                            className="bg-card-muted border border-border rounded-lg px-3 py-1.5 text-xs text-foreground w-24 focus:outline-none focus:ring-2 focus:ring-blue/20" />
                    </Row>
                </Section>
            </div>
    );
}
