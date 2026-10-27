import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';

/**
 * Large centered headline treatment for the abstract (non-dashboard) beats — scene opens/closes,
 * the decision-cycle title, etc. Deterministic fade+rise keyed off `appearFrame` (local frame).
 */
export const TitleCard: React.FC<{
  kicker?: string;
  lines: string[];
  appearFrame: number;
  size?: number;
  align?: 'center' | 'left';
}> = ({ kicker, lines, appearFrame, size = 44, align = 'center' }) => {
  const frame = useCurrentFrame();
  const local = frame - appearFrame;
  const opacity = interpolate(local, [0, 16], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const translateY = interpolate(local, [0, 16], [20, 0], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });

  return (
    <div
      style={{
        opacity,
        transform: `translateY(${translateY}px)`,
        display: 'flex',
        flexDirection: 'column',
        alignItems: align === 'center' ? 'center' : 'flex-start',
        gap: 14,
        textAlign: align,
      }}
    >
      {kicker && (
        <div
          style={{
            fontFamily: 'JetBrains Mono',
            fontSize: 16,
            letterSpacing: '0.18em',
            color: tokens.vz.prog4,
            textTransform: 'uppercase',
          }}
        >
          {kicker}
        </div>
      )}
      {lines.map((line, i) => (
        <div
          key={i}
          style={{
            fontFamily: 'Space Grotesk',
            fontWeight: 800,
            fontSize: size,
            lineHeight: 1.25,
            letterSpacing: '-0.01em',
            color: tokens.surface.foreground,
            maxWidth: 1400,
          }}
        >
          {line}
        </div>
      ))}
    </div>
  );
};
