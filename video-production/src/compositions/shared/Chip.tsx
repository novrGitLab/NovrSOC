import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';

export const Chip: React.FC<{
  label: string;
  sub?: string;
  tone?: 'neutral' | 'verified' | 'conceptual';
  appearFrame: number;
  style?: React.CSSProperties;
}> = ({ label, sub, tone = 'neutral', appearFrame, style }) => {
  const frame = useCurrentFrame();
  const local = frame - appearFrame;
  const opacity = interpolate(local, [0, 12], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const scale = interpolate(local, [0, 12], [0.9, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

  const dotColor = tone === 'verified' ? tokens.vz.good : tone === 'conceptual' ? tokens.surface.foregroundMuted : tokens.vz.prog4;

  return (
    <div
      style={{
        opacity,
        transform: `scale(${scale})`,
        background: tokens.surface.card,
        border: `1px solid ${tokens.surface.border}`,
        borderRadius: 14,
        padding: '12px 18px',
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        minWidth: 160,
        ...style,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ width: 7, height: 7, borderRadius: 999, background: dotColor }} />
        <span style={{ fontFamily: 'Inter', fontWeight: 600, fontSize: 14, color: tokens.surface.foreground }}>
          {label}
        </span>
      </div>
      {sub && (
        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 10.5, letterSpacing: '0.04em', color: tokens.surface.foregroundMuted }}>
          {sub}
        </span>
      )}
    </div>
  );
};
