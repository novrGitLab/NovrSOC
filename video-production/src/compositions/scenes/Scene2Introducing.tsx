import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';
import { Logo } from '../shared/Logo';

const TAGLINES = ['Built in Nigeria.', 'One Platform. Connected Security.', 'See. Prioritize. Act. Communicate.'];
const LOGO_START = 20;
const TAGLINE_START = 170;
const TAGLINE_STAGGER = 130;

export const Scene2Introducing: React.FC = () => {
  const frame = useCurrentFrame();

  const logoOpacity = interpolate(frame - LOGO_START, [0, 30], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
  const logoScale = interpolate(frame - LOGO_START, [0, 30], [0.82, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  return (
    <AbsoluteFill
      style={{
        background: tokens.surface.surface,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 56,
      }}
    >
      <div style={{ opacity: logoOpacity, transform: `scale(${logoScale})` }}>
        <Logo height={150} />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 18, alignItems: 'center' }}>
        {TAGLINES.map((line, i) => {
          const start = TAGLINE_START + i * TAGLINE_STAGGER;
          const opacity = interpolate(frame - start, [0, 20], [0, 1], {
            extrapolateLeft: 'clamp',
            extrapolateRight: 'clamp',
          });
          const translateY = interpolate(frame - start, [0, 20], [14, 0], {
            extrapolateLeft: 'clamp',
            extrapolateRight: 'clamp',
          });
          return (
            <div
              key={line}
              style={{
                opacity,
                transform: `translateY(${translateY}px)`,
                fontFamily: 'Space Grotesk',
                fontWeight: i === 0 ? 700 : 600,
                fontSize: i === 0 ? 30 : 24,
                color: i === 0 ? tokens.surface.foreground : tokens.surface.foregroundMuted,
                letterSpacing: '-0.01em',
              }}
            >
              {line}
            </div>
          );
        })}
      </div>
    </AbsoluteFill>
  );
};
