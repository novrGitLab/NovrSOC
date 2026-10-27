import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';

export interface SeveritySlice {
  key: 'critical' | 'high' | 'medium' | 'low' | 'info';
  label: string;
  value: number;
  color: string;
}

export const SEVERITY_SLICES = (counts: Record<string, number>): SeveritySlice[] => [
  { key: 'critical', label: 'Critical', value: counts.critical ?? 0, color: tokens.vz.sevCritical },
  { key: 'high', label: 'High', value: counts.high ?? 0, color: tokens.vz.sevHigh },
  { key: 'medium', label: 'Medium', value: counts.medium ?? 0, color: tokens.vz.sevMedium },
  { key: 'low', label: 'Low', value: counts.low ?? 0, color: tokens.vz.sevLow },
  { key: 'info', label: 'Informational', value: counts.info ?? 0, color: tokens.vz.sevInfo },
];

/**
 * Mirrors the real app's severity donut (features/vms/charts.tsx `Donut`), reusing the same
 * --vz-sev-* color mapping. Draws progressively via stroke-dashoffset, frame-driven.
 */
export const SeverityDonut: React.FC<{
  slices: SeveritySlice[];
  appearFrame: number;
  drawDurationFrames?: number;
  size?: number;
}> = ({ slices, appearFrame, drawDurationFrames = 50, size = 220 }) => {
  const frame = useCurrentFrame();
  const localFrame = frame - appearFrame;
  const progress = interpolate(localFrame, [0, drawDurationFrames], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const total = slices.reduce((s, x) => s + x.value, 0) || 1;
  const radius = size / 2 - 18;
  const circumference = 2 * Math.PI * radius;
  const cx = size / 2;
  const cy = size / 2;

  let cumulative = 0;
  const arcs = slices.map((slice) => {
    const fraction = slice.value / total;
    const start = cumulative;
    cumulative += fraction;
    return { ...slice, start, fraction };
  });

  // Sweep reveal: a single "progress" boundary moves around the ring (0 -> 1 of total
  // circumference). A segment is drawn up to wherever that boundary currently sits.
  const centerCount = Math.round(total * progress);

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 28 }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke={tokens.vz.grid}
          strokeWidth={22}
        />
        {arcs.map((arc) => {
          // How much of THIS segment is within the swept boundary [0, progress].
          const drawnFraction = Math.max(0, Math.min(arc.fraction, progress - arc.start));
          const arcLength = drawnFraction * circumference;
          const offset = arc.start * circumference;
          return (
            <circle
              key={arc.key}
              cx={cx}
              cy={cy}
              r={radius}
              fill="none"
              stroke={arc.color}
              strokeWidth={22}
              strokeDasharray={`${arcLength} ${circumference - arcLength}`}
              strokeDashoffset={-offset}
              strokeLinecap="butt"
            />
          );
        })}
      </svg>
      <div
        style={{
          position: 'absolute',
          left: size / 2 - 40,
          width: 80,
          textAlign: 'center',
        }}
      >
        <div
          style={{
            fontFamily: 'JetBrains Mono',
            fontWeight: 700,
            fontSize: 30,
            color: tokens.surface.foreground,
          }}
        >
          {centerCount}
        </div>
        <div style={{ fontFamily: 'Inter', fontSize: 11, color: tokens.surface.foregroundMuted }}>
          open
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {slices.map((slice, i) => {
          const rowDelay = appearFrame + 10 + i * 4;
          const rowOpacity = interpolate(frame - rowDelay, [0, 10], [0, 1], {
            extrapolateLeft: 'clamp',
            extrapolateRight: 'clamp',
          });
          return (
            <div
              key={slice.key}
              style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: rowOpacity }}
            >
              <div style={{ width: 10, height: 10, borderRadius: 3, background: slice.color }} />
              <span style={{ fontFamily: 'Inter', fontSize: 13, color: tokens.surface.foreground }}>
                {slice.label}
              </span>
              <span
                style={{
                  fontFamily: 'JetBrains Mono',
                  fontSize: 13,
                  color: tokens.surface.foregroundMuted,
                  marginLeft: 4,
                }}
              >
                {slice.value}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
