'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
    Bell, Send, Mail, Phone, Zap, RefreshCw,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

interface ChannelStatus {
    configured: boolean;
    name: string;
    description: string;
}

interface AlertChannels {
    email: ChannelStatus;
    sms: ChannelStatus;
    pagerduty: ChannelStatus;
}

const CHANNEL_ICONS: Record<string, LucideIcon> = { email: Mail, sms: Phone, pagerduty: Zap };

const TABS = [
    { id: 'channels', label: 'Channels' },
    { id: 'history', label: 'Alert History' },
    { id: 'send', label: 'Send Alert' },
    { id: 'email', label: 'Email' },
] as const;
type Tab = (typeof TABS)[number]['id'];

interface EmailStatus {
    enabled: boolean;
    provider: string;
    from: string;
    configured: boolean;
}

const ALERT_THRESHOLDS = [
    { level: 'Critical (Level 12+)', enabled: true },
    { level: 'High (Level 9-11)', enabled: true },
    { level: 'Medium (Level 6-8)', enabled: false },
    { level: 'Low (Level 3-5)', enabled: false },
];

export function AlertCommunication() {
    const [channels, setChannels] = useState<AlertChannels | null>(null);
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState<string | null>(null);
    const [sendForm, setSendForm] = useState({ title: '', severity: 'high', description: '', host: '' });
    const [sending, setSending] = useState(false);
    const [sendResult, setSendResult] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<Tab>('channels');
    const [emailStatus, setEmailStatus] = useState<EmailStatus | null>(null);
    const [testEmailTo, setTestEmailTo] = useState('');
    const [testingEmail, setTestingEmail] = useState(false);
    const [testEmailResult, setTestEmailResult] = useState<{ ok: boolean; message: string } | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/alerts/status'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setChannels(d.channels ?? null))
            .catch(() => {});
        apiFetch(apiUrl('/api/email/status'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setEmailStatus(d ?? null))
            .catch(() => {});
    }, []);

    const sendTestEmail = async () => {
        if (!testEmailTo) return;
        setTestingEmail(true);
        setTestEmailResult(null);
        try {
            const res = await apiFetch(apiUrl('/api/email/test'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ to: testEmailTo }),
            });
            const data = await res.json();
            setTestEmailResult({ ok: res.ok && data.success, message: data.message || data.error || 'Unknown response' });
        } catch {
            setTestEmailResult({ ok: false, message: 'Test email failed — check console' });
        } finally {
            setTestingEmail(false);
        }
    };

    const sendTest = async () => {
        setTesting(true);
        setTestResult(null);
        try {
            const res = await apiFetch(apiUrl('/api/alerts/test'), { method: 'POST' });
            const data = await res.json();
            setTestResult(data.message);
        } catch {
            setTestResult('Test failed — check console');
        } finally {
            setTesting(false);
        }
    };

    const sendAlert = async () => {
        if (!sendForm.title) return;
        setSending(true);
        setSendResult(null);
        try {
            const res = await apiFetch(apiUrl('/api/alerts/incident'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: sendForm.title,
                    severity: sendForm.severity,
                    description: sendForm.description,
                    affected_host: sendForm.host,
                }),
            });
            const data = await res.json();
            setSendResult(data.message);
        } catch {
            setSendResult('Send failed');
        } finally {
            setSending(false);
        }
    };

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Alert Communication</h1>
                <p className="text-xs text-foreground-muted">SecOps & Response · Incident notifications to the SOC team. Email is live; SMS and PagerDuty light up once their keys are set.</p>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
                {TABS.map((t) => (
                    <button key={t.id} onClick={() => setActiveTab(t.id)}
                        className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-colors ${activeTab === t.id ? 'border-blue text-blue' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>
                        {t.label}
                    </button>
                ))}
            </div>

            {/* CHANNELS TAB */}
            {activeTab === 'channels' && (
                <div className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {channels && Object.entries(channels).map(([key, channel]) => {
                            const Icon = CHANNEL_ICONS[key] ?? Bell;
                            return (
                                <div key={key} className={`bg-card border rounded-xl p-5 ${channel.configured ? 'border-border' : 'border-dashed border-grey-300'}`}>
                                    <div className="flex items-start justify-between mb-3 gap-3">
                                        <div className="flex items-center gap-3 min-w-0">
                                            <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${channel.configured ? 'bg-blue/10' : 'bg-card-muted'}`}>
                                                <Icon size={20} className={channel.configured ? 'text-blue' : 'text-grey-300'} />
                                            </div>
                                            <div className="min-w-0">
                                                <div className="font-medium text-sm text-foreground">{channel.name}</div>
                                                <div className="text-xs text-foreground-muted truncate">{channel.description}</div>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-1.5 flex-shrink-0">
                                            <div className={`w-2 h-2 rounded-full ${channel.configured ? 'bg-green' : 'bg-grey-300'}`} />
                                            <span className={`text-xs font-medium ${channel.configured ? 'text-green' : 'text-foreground-muted'}`}>{channel.configured ? 'Active' : 'Not configured'}</span>
                                        </div>
                                    </div>

                                    {!channel.configured && (
                                        <div className="text-xs text-foreground-muted bg-card-muted rounded-lg p-2">
                                            {key === 'sms' && 'Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER to .env'}
                                            {key === 'pagerduty' && 'Add PAGERDUTY_API_KEY to .env ($21/user/month)'}
                                            {key === 'email' && 'Set EMAIL_ENABLED=true and RESEND_API_KEY on Railway (sender: alerts@cybernovr.com)'}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>

                    {/* Test button */}
                    <div className="bg-card border border-border rounded-xl p-5">
                        <div className="flex items-center justify-between gap-3 flex-wrap">
                            <div>
                                <div className="font-medium text-sm text-foreground">Test Alert Channels</div>
                                <div className="text-xs text-foreground-muted">Sends a test alert by email to the SOC mailbox</div>
                            </div>
                            <button onClick={sendTest} disabled={testing}
                                className="flex items-center gap-2 bg-blue hover:opacity-90 text-white text-xs font-bold px-4 py-2 rounded-lg disabled:opacity-50 transition-colors">
                                {testing ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />}
                                {testing ? 'Sending…' : 'Send Test'}
                            </button>
                        </div>
                        {testResult && (
                            <div className="mt-3 text-sm text-green bg-green/10 border border-green/30 rounded-lg px-3 py-2">{testResult}</div>
                        )}
                    </div>

                    {/* Escalation rules */}
                    <div className="bg-card border border-border rounded-xl p-5">
                        <h3 className="font-heading font-semibold text-sm text-foreground mb-4">Escalation Rules</h3>
                        <div className="space-y-3">
                            {[
                                { severity: 'CRITICAL', rule: 'Case + CISO email', threshold: 'Rule level ≥ 13' },
                                { severity: 'HIGH', rule: 'Case + SOC email', threshold: 'Rule level ≥ 10' },
                                { severity: 'MEDIUM', rule: 'Case, auto-closed', threshold: 'Rule level ≥ 7' },
                                { severity: 'LOW', rule: 'Log only', threshold: 'Rule level < 7' },
                            ].map((row) => (
                                <div key={row.severity} className="flex items-center justify-between text-sm flex-wrap gap-2">
                                    <div className="flex items-center gap-2">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                                            row.severity === 'CRITICAL' ? 'bg-red-500 text-white' :
                                            row.severity === 'HIGH' ? 'bg-amber text-white' :
                                            row.severity === 'MEDIUM' ? 'border border-amber/40 text-amber' :
                                            'border border-grey-300 text-foreground-muted'
                                        }`}>{row.severity}</span>
                                        <span className="text-foreground-muted text-xs">{row.threshold}</span>
                                    </div>
                                    <span className="text-xs text-foreground font-medium">{row.rule}</span>
                                </div>
                            ))}
                        </div>
                        <div className="mt-3 text-xs text-foreground-muted">
                            Applied by the SOAR engine on the Wazuh manager (infra/soar). SMS and PagerDuty are not part of the pipeline yet.
                        </div>
                    </div>
                </div>
            )}

            {/* HISTORY TAB */}
            {activeTab === 'history' && (
                <div className="bg-card border border-dashed border-border rounded-xl p-8 text-center">
                    <p className="text-sm font-bold text-foreground">No dispatch history is stored yet</p>
                    <p className="text-xs text-foreground-muted mt-1 max-w-md mx-auto">
                        Manual alerts sent from this page are not recorded. Automated notifications are: each case&apos;s timeline
                        shows every email the SOAR engine or an analyst sent for it, and SOAR Automation lists the engine&apos;s actions.
                    </p>
                    <div className="flex items-center justify-center gap-4 mt-4 text-xs font-bold">
                        <Link href="/admin/secops/cases" className="text-purple hover:underline">Cases →</Link>
                        <Link href="/admin/secops/soar" className="text-purple hover:underline">SOAR Automation →</Link>
                    </div>
                </div>
            )}

            {/* SEND TAB */}
            {activeTab === 'send' && (
                <div className="bg-card border border-border rounded-xl p-6 max-w-lg">
                    <h3 className="font-heading font-semibold text-sm text-foreground mb-4">Send Manual Alert</h3>
                    <div className="space-y-4">
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Alert Title</label>
                            <input
                                type="text"
                                value={sendForm.title}
                                onChange={(e) => setSendForm((f) => ({ ...f, title: e.target.value }))}
                                placeholder="e.g. Suspicious login from unknown IP"
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 text-foreground"
                            />
                        </div>
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Severity</label>
                            <select
                                value={sendForm.severity}
                                onChange={(e) => setSendForm((f) => ({ ...f, severity: e.target.value }))}
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue text-foreground"
                            >
                                {['critical', 'high', 'medium', 'low'].map((s) => (
                                    <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Description</label>
                            <textarea
                                value={sendForm.description}
                                onChange={(e) => setSendForm((f) => ({ ...f, description: e.target.value }))}
                                placeholder="Describe the incident…"
                                rows={3}
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 text-foreground resize-none"
                            />
                        </div>
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Affected Host</label>
                            <input
                                type="text"
                                value={sendForm.host}
                                onChange={(e) => setSendForm((f) => ({ ...f, host: e.target.value }))}
                                placeholder="e.g. ec2-app-server"
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 text-foreground"
                            />
                        </div>
                        <button
                            onClick={sendAlert}
                            disabled={sending || !sendForm.title}
                            className="w-full flex items-center justify-center gap-2 bg-orange hover:bg-orange-hover text-white text-sm font-semibold py-2.5 rounded-lg disabled:opacity-50 transition-colors"
                        >
                            {sending ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />}
                            {sending ? 'Dispatching…' : 'Dispatch Alert'}
                        </button>
                        {sendResult && (
                            <div className="text-sm text-green bg-green/10 border border-green/30 rounded-lg px-3 py-2">{sendResult}</div>
                        )}
                    </div>
                </div>
            )}

            {/* EMAIL TAB */}
            {activeTab === 'email' && (
                <div className="space-y-4 max-w-2xl">
                    {/* Status card */}
                    <div className={`rounded-xl p-4 border flex items-center gap-4 ${emailStatus?.enabled ? 'bg-green/10 border-green/30' : 'bg-card-muted border-dashed border-grey-300'}`}>
                        <div className={`w-3 h-3 rounded-full flex-shrink-0 ${emailStatus?.enabled ? 'bg-green' : 'bg-amber'}`} />
                        <div className="min-w-0">
                            <div className="font-medium text-sm text-foreground">
                                {emailStatus?.enabled ? 'Email alerts active' : 'Email not configured'}
                            </div>
                            <div className="text-xs text-foreground-muted">
                                {emailStatus?.enabled
                                    ? `Sending from ${emailStatus.from} via SendGrid`
                                    : 'Add SENDGRID_API_KEY and set EMAIL_ENABLED=true in the backend environment'}
                            </div>
                        </div>
                    </div>

                    {/* Alert thresholds — mirrors the escalation rules on the Channels tab; not yet
                       editable here, this documents which severities trigger a SendGrid email today. */}
                    <div className="bg-card border border-border rounded-xl p-5">
                        <h3 className="font-heading font-semibold text-sm text-foreground mb-4">Alert Email Thresholds</h3>
                        {ALERT_THRESHOLDS.map((item) => (
                            <div key={item.level} className="flex items-center justify-between py-2.5 border-b border-border last:border-0">
                                <span className="text-sm font-medium text-foreground">{item.level}</span>
                                <div className={`w-10 h-5 rounded-full transition-colors ${item.enabled ? 'bg-blue' : 'bg-card-muted'}`} />
                            </div>
                        ))}
                    </div>

                    {/* Recipients */}
                    <div className="bg-card border border-border rounded-xl p-5">
                        <h3 className="font-heading font-semibold text-sm text-foreground mb-4">Critical Alert Recipients</h3>
                        <p className="text-xs text-foreground-muted mb-3">
                            Set via <span className="font-mono">ALERT_EMAIL_TO</span> in the backend environment. Recipient management from this page isn&apos;t wired up yet.
                        </p>
                    </div>

                    {/* Send test email */}
                    <div className="bg-card border border-border rounded-xl p-5">
                        <h3 className="font-heading font-semibold text-sm text-foreground mb-4">Send Test Email</h3>
                        <div className="flex gap-2">
                            <input
                                type="email"
                                value={testEmailTo}
                                onChange={(e) => setTestEmailTo(e.target.value)}
                                placeholder="you@company.com"
                                className="flex-1 border border-border bg-card-muted rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 text-foreground"
                            />
                            <button
                                onClick={sendTestEmail}
                                disabled={testingEmail || !testEmailTo}
                                className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2 rounded-lg disabled:opacity-50 transition-colors"
                            >
                                {testingEmail ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />}
                                {testingEmail ? 'Sending…' : 'Send Test'}
                            </button>
                        </div>
                        {testEmailResult && (
                            <div className={`mt-3 text-sm rounded-lg px-3 py-2 border ${testEmailResult.ok ? 'text-green bg-green/10 border-green/30' : 'text-red-500 bg-red-500/10 border-red-500/30'}`}>
                                {testEmailResult.message}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
