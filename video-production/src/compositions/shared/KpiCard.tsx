import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';

export type KpiTone = 'neutral' | 'good' | 'warning' | 'critical';

const TONE_COLOR: Record<KpiTone, string> = {
  neutral: tokens.surface.foregroundMuted,
  good: tokens.vz.good,
  warning: tokens.vz.warning,
  critical: tokens.vz.critical,
};

/**
 * Mirrors the real app's KpiCard (frontend/src/components/features/vms/kit.tsx):
 * muted label, large bold number (count-up), optional tone dot, optional sub-line.
 * Here the count-up is driven by the Remotion frame clock instead of client state,
 * so it renders identically on every run (deterministic).
 */
export const KpiCard: React.FC<{
  label: string;
  value: number;
  suffix?: string;
  sub?: string;
  tone?: KpiTone;
  appearFrame: number;
  countDurationFrames?: number;
}> = ({ label, value, suffix = '', sub, tone = 'neutral', appearFrame, countDurationFrames = 24 }) => {
  const frame = useCurrentFrame();
  const localFrame = frame - appearFrame;

  const appear = interpolate(localFrame, [0, 14], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
  const translateY = interpolate(localFrame, [0, 14], [16, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const countProgress = interpolate(
    localFrame,
    [6, 6 + countDurationFrames],
    [0, 1],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );
  // ease-out cubic
  const eased = 1 - Math.pow(1 - countProgress, 3);
  const displayValue = Math.round(value * eased);

  return (
    <div
      style={{
        opacity: appear,
        transform: `translateY(${translateY}px)`,
        background: tokens.surface.card,
        border: `1px solid ${tokens.surface.border}`,
        borderRadius: 20,
        padding: '20px 22px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        minHeight: 128,
        boxShadow: '0 1px 2px rgba(0,0,0,0.3)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <span
          style={{
            fontFamily: 'Inter',
            fontSize: 13,
            fontWeight: 600,
            color: tokens.surface.foregroundMuted,
            lineHeight: 1.3,
          }}
        >
          {label}
        </span>
        {tone !== 'neutral' && (
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: 999,
              background: TONE_COLOR[tone],
              marginTop: 4,
            }}
          />
        )}
      </div>
      <div
        style={{
          fontFamily: 'JetBrains Mono',
          fontWeight: 700,
          fontSize: 38,
          color: tokens.surface.foreground,
          letterSpacing: '-0.01em',
        }}
      >
        {displayValue.toLocaleString('en-US')}
        {suffix}
      </div>
      {sub && (
        <div style={{ fontFamily: 'Inter', fontSize: 12, color: tokens.surface.foregroundMuted }}>
          {sub}
        </div>
      )}
    </div>
  );
};
