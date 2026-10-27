import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../lib/tokens';
import { Sidebar } from './shared/Sidebar';
import { PageHeader } from './shared/PageHeader';
import { KpiCard } from './shared/KpiCard';
import { SEVERITY_SLICES, SeverityDonut } from './shared/SeverityDonut';

// Frame markers (30fps). Empty shell -> shell slides in -> KPIs stagger in with count-up ->
// severity donut draws -> hold for readability. Mirrors the real VmsDashboard.tsx KPI set:
// Total assets, Open vulnerabilities, Critical vulnerabilities, Critical exposures,
// Overdue remediation tasks, Active scans (frontend/src/components/features/vms/VmsDashboard.tsx).
const SIDEBAR_START = 10;
const SIDEBAR_DURATION = 18;
const HEADER_START = 24;
const KPI_START = 40;
const KPI_STAGGER = 6;
const DONUT_START = 150;

// Synthetic demo data only — consistent with real field names/severity levels, not real counts.
const KPI_DATA = [
  { label: 'Total assets', value: 482, sub: '96 internet-facing' },
  { label: 'Open vulnerabilities', value: 1247, sub: '58 informational not counted' },
  { label: 'Critical vulnerabilities', value: 14, tone: 'critical' as const, sub: 'Open, scanner severity critical' },
  { label: 'Critical exposures', value: 9, tone: 'warning' as const, sub: 'Critical/high on internet-facing assets' },
  { label: 'Overdue remediation tasks', value: 6, tone: 'warning' as const, sub: '11 findings past deadline' },
  { label: 'Active scans', value: 3, sub: 'Queued or running now' },
];

const SEVERITY_COUNTS = { critical: 14, high: 162, medium: 410, low: 598, info: 63 };

export const VmsDashboardPrototype: React.FC = () => {
  const frame = useCurrentFrame();

  const sidebarProgress = interpolate(
    frame,
    [SIDEBAR_START, SIDEBAR_START + SIDEBAR_DURATION],
    [0, 1],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );

  const headerOpacity = interpolate(frame - HEADER_START, [0, 16], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
  const headerTranslate = interpolate(frame - HEADER_START, [0, 16], [12, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const contentLeft = interpolate(sidebarProgress, [0, 1], [0, 240]);

  return (
    <AbsoluteFill style={{ background: tokens.surface.surface }}>
      <Sidebar slideInProgress={sidebarProgress} />

      <div
        style={{
          position: 'absolute',
          top: 0,
          left: contentLeft,
          right: 0,
          bottom: 0,
          padding: '48px 56px',
          display: 'flex',
          flexDirection: 'column',
          gap: 32,
        }}
      >
        <PageHeader
          title="VMS Dashboard"
          description="Exposure, vulnerabilities, remediation and scanning for this organisation — every figure is counted from stored records; nothing is estimated."
          opacity={headerOpacity}
          translateY={headerTranslate}
        />

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: 20,
          }}
        >
          {KPI_DATA.map((kpi, i) => (
            <KpiCard
              key={kpi.label}
              label={kpi.label}
              value={kpi.value}
              sub={kpi.sub}
              tone={kpi.tone}
              appearFrame={KPI_START + i * KPI_STAGGER}
            />
          ))}
        </div>

        <div
          style={{
            background: tokens.surface.card,
            border: `1px solid ${tokens.surface.border}`,
            borderRadius: 20,
            padding: '28px 32px',
            position: 'relative',
            opacity: interpolate(frame - DONUT_START, [0, 10], [0, 1], {
              extrapolateLeft: 'clamp',
              extrapolateRight: 'clamp',
            }),
          }}
        >
          <div
            style={{
              fontFamily: 'Inter',
              fontWeight: 600,
              fontSize: 14,
              color: tokens.surface.foreground,
              marginBottom: 20,
            }}
          >
            Open findings by severity
          </div>
          <SeverityDonut
            slices={SEVERITY_SLICES(SEVERITY_COUNTS)}
            appearFrame={DONUT_START}
            drawDurationFrames={55}
          />
        </div>
      </div>

      {/* Synthetic-data label, following the product's own convention for non-live data
          (see frontend/src/components/features/CloudAssets.tsx). */}
      <div
        style={{
          position: 'absolute',
          bottom: 24,
          right: 32,
          fontFamily: 'JetBrains Mono',
          fontSize: 12,
          letterSpacing: '0.08em',
          color: tokens.surface.foregroundMuted,
          background: tokens.surface.cardMuted,
          border: `1px solid ${tokens.surface.border}`,
          borderRadius: 8,
          padding: '6px 12px',
          opacity: 0.9,
        }}
      >
        SYNTHETIC DEMO DATA
      </div>
    </AbsoluteFill>
  );
};
