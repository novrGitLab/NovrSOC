'use client';

import { Cloud } from 'lucide-react';

// Cloud asset monitoring — not yet connected to anything.
//
// This page is explicitly a roadmap placeholder and says so on screen. It shows no counts, no
// charts and no sample resources: a cloud page that renders "12 EC2 instances" from nothing is
// indistinguishable from a working integration, and an analyst would reasonably believe their
// AWS account was being monitored when it is not. The Connect buttons are disabled for the same
// reason — there is no OAuth flow or credential store behind them yet.

const PROVIDERS = [
    {
        id: 'aws',
        icon: '☁️',
        name: 'Amazon Web Services',
        tagline: 'EC2, S3, RDS, Lambda monitoring',
        blurb: 'Connect an AWS account to monitor EC2 instances, S3 bucket access policies, IAM changes and CloudTrail events alongside your on-premise Wazuh agents.',
        signals: ['CloudTrail event ingestion', 'S3 public-access detection', 'IAM privilege changes', 'EC2 instance inventory'],
    },
    {
        id: 'azure',
        icon: '🔷',
        name: 'Microsoft Azure',
        tagline: 'VMs, Storage, Entra ID monitoring',
        blurb: 'Connect an Azure subscription to pull Activity Log events, Entra ID sign-ins and storage account configuration into the same incident pipeline.',
        signals: ['Activity Log ingestion', 'Entra ID risky sign-ins', 'Storage account exposure', 'VM inventory'],
    },
    {
        id: 'gcp',
        icon: '🌤️',
        name: 'Google Cloud Platform',
        tagline: 'Compute Engine, Cloud Storage, IAM',
        blurb: 'Connect a GCP project to ingest Cloud Audit Logs, monitor bucket IAM bindings and track Compute Engine instances.',
        signals: ['Cloud Audit Log ingestion', 'Bucket IAM monitoring', 'Service account key age', 'Compute inventory'],
    },
];

export function CloudAssets() {
    return (
        <div className="space-y-4">
            <div className="flex items-start gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-blue/10 flex items-center justify-center shrink-0">
                    <Cloud className="w-4 h-4 text-blue" />
                </div>
                <div>
                    <h1 className="text-lg font-black text-foreground">Cloud Assets</h1>
                    <p className="text-xs text-foreground-muted">Infrastructure &amp; Assets · Cloud account monitoring</p>
                </div>
            </div>

            <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl p-4">
                <p className="text-sm font-bold text-amber-500">Not connected — planned for Phase 2</p>
                <p className="text-xs text-foreground-muted mt-1 leading-relaxed">
                    No cloud accounts are linked, and nothing on this page reflects live infrastructure.
                    Endpoint coverage today comes from the Wazuh agents listed under{' '}
                    <a href="/admin/infra/assets" className="text-purple hover:underline">Digital Assets</a>.
                </p>
            </div>

            <div className="space-y-4">
                {PROVIDERS.map((p) => (
                    <div key={p.id} className="bg-card border border-border rounded-2xl p-5">
                        <div className="flex items-center gap-3 mb-3 flex-wrap">
                            <span className="text-3xl">{p.icon}</span>
                            <div className="min-w-0">
                                <h3 className="font-bold text-sm text-foreground">{p.name}</h3>
                                <p className="text-[11px] text-foreground-muted">{p.tagline}</p>
                            </div>
                            <button
                                disabled
                                title="Cloud integrations are not available yet"
                                className="ml-auto text-xs font-bold bg-card-muted text-foreground-muted px-4 py-2 rounded-xl cursor-not-allowed border border-border"
                            >
                                Connect {p.name.split(' ')[0]}
                            </button>
                        </div>
                        <p className="text-xs text-foreground-muted leading-relaxed mb-3">{p.blurb}</p>
                        <div className="flex gap-1.5 flex-wrap">
                            {p.signals.map((s) => (
                                <span key={s} className="text-[10px] bg-card-muted text-foreground-muted px-2 py-1 rounded-full">{s}</span>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
