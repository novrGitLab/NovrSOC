import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';

// Labels mirror real top-level nav groups from frontend/src/config/nav.ts (Overview, Sec Ops,
// VMS, Threat Intel, CNII, Brand, Infra, Email, Compliance) — order/icons simplified for video.
const NAV_ITEMS = [
  { label: 'Dashboard', active: false },
  { label: 'Sec Ops', active: false },
  { label: 'VMS', active: true },
  { label: 'Threat Intel', active: false },
  { label: 'CNII Watch', active: false },
  { label: 'Brand Protection', active: false },
  { label: 'Infrastructure', active: false },
  { label: 'Email Security', active: false },
  { label: 'Compliance', active: false },
];

export const Sidebar: React.FC<{ slideInProgress: number; width?: number }> = ({
  slideInProgress,
  width = 240,
}) => {
  const frame = useCurrentFrame();
  const translateX = interpolate(slideInProgress, [0, 1], [-width, 0]);

  return (
    <div
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width,
        height: '100%',
        background: tokens.surface.card,
        borderRight: `1px solid ${tokens.surface.border}`,
        transform: `translateX(${translateX}px)`,
        display: 'flex',
        flexDirection: 'column',
        padding: '28px 0',
      }}
    >
      <div
        style={{
          fontFamily: 'Space Grotesk',
          fontWeight: 800,
          fontSize: 22,
          color: tokens.surface.foreground,
          padding: '0 24px',
          marginBottom: 36,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
      >
        <span style={{ color: tokens.vz.prog4 }}>Novr</span>
        <span>SOC</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {NAV_ITEMS.map((item, i) => {
          const rowDelay = i * 2;
          const rowOpacity = interpolate(frame - rowDelay, [20, 30], [0, 1], {
            extrapolateLeft: 'clamp',
            extrapolateRight: 'clamp',
          });
          return (
            <div
              key={item.label}
              style={{
                margin: '0 12px',
                padding: '10px 14px',
                borderRadius: 10,
                background: item.active ? tokens.surface.cardMuted : 'transparent',
                color: item.active ? tokens.surface.foreground : tokens.surface.foregroundMuted,
                fontFamily: 'Inter',
                fontSize: 13,
                fontWeight: item.active ? 600 : 500,
                opacity: rowOpacity,
              }}
            >
              {item.label}
            </div>
          );
        })}
      </div>
    </div>
  );
};
