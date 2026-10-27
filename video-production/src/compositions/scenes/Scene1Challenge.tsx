import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';

// Generic security-tool categories (not NovrSOC-specific claims) — deterministic fixed start
// positions, no Math.random(), so every render is pixel-identical.
const TOOLS = [
  { label: 'Firewall', x0: 170, y0: 150 },
  { label: 'EDR Alerts', x0: 1520, y0: 210 },
  { label: 'Cloud Logs', x0: 230, y0: 770 },
  { label: 'Threat Feed', x0: 1480, y0: 830 },
  { label: 'Email Gateway', x0: 840, y0: 110 },
  { label: 'Identity Provider', x0: 880, y0: 900 },
];

const CARD_W = 220;
const CARD_H = 90;
const GRID_GAP = 20;
const GRID_START_X = 960 - (3 * CARD_W + 2 * GRID_GAP) / 2;
const GRID_START_Y = 540 - (2 * CARD_H + GRID_GAP) / 2;

const CONVERGE_START = 560;
const CONVERGE_END = 860;

const windowOpacity = (frame: number, inStart: number, inEnd: number, outStart: number, outEnd: number) =>
  interpolate(frame, [inStart, inEnd, outStart, outEnd], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

export const Scene1Challenge: React.FC = () => {
  const frame = useCurrentFrame();

  const convergeProgress = interpolate(frame, [CONVERGE_START, CONVERGE_END], [0, 1], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });
  const eased = 1 - Math.pow(1 - convergeProgress, 3);

  const headline1Opacity = windowOpacity(frame, 130, 160, 480, 540);
  const headline2Opacity = windowOpacity(frame, 900, 940, 1020, 1050);

  return (
    <AbsoluteFill style={{ background: tokens.surface.surface }}>
      {TOOLS.map((tool, i) => {
        // Gentle deterministic drift before convergence — a slow sine wave per card, offset by
        // index so cards don't move in lockstep.
        const drift = Math.sin((frame + i * 40) / 55) * (1 - eased) * 14;

        const col = i % 3;
        const row = Math.floor(i / 3);
        const x1 = GRID_START_X + col * (CARD_W + GRID_GAP);
        const y1 = GRID_START_Y + row * (CARD_H + GRID_GAP);

        const x = tool.x0 + (x1 - tool.x0) * eased;
        const y = tool.y0 + (y1 - tool.y0) * eased + drift;

        return (
          <div
            key={tool.label}
            style={{
              position: 'absolute',
              left: x,
              top: y,
              width: CARD_W,
              height: CARD_H,
              borderRadius: 16,
              background: tokens.surface.card,
              border: `1px solid ${eased > 0.9 ? tokens.vz.prog4 : tokens.surface.border}`,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              padding: '0 18px',
              gap: 6,
              boxShadow: '0 8px 24px rgba(0,0,0,0.35)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: 999,
                  background: tokens.vz.sevHigh,
                  opacity: interpolate(Math.sin((frame + i * 17) / 10), [-1, 1], [0.4, 1]),
                }}
              />
              <span style={{ fontFamily: 'Inter', fontWeight: 600, fontSize: 15, color: tokens.surface.foreground }}>
                {tool.label}
              </span>
            </div>
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: tokens.surface.foregroundMuted }}>
              isolated signal
            </span>
          </div>
        );
      })}

      {/* Headline 1 */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'flex-start',
          paddingTop: 90,
          opacity: headline1Opacity,
        }}
      >
        <div
          style={{
            fontFamily: 'Space Grotesk',
            fontWeight: 800,
            fontSize: 42,
            color: tokens.surface.foreground,
            textAlign: 'center',
            maxWidth: 1100,
            lineHeight: 1.3,
          }}
        >
          Disconnected tools. Fragmented intelligence. Delayed response.
        </div>
      </div>

      {/* Headline 2 — appears once cards have converged */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '100%',
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'center',
          paddingBottom: 110,
          opacity: headline2Opacity,
        }}
      >
        <div
          style={{
            fontFamily: 'Space Grotesk',
            fontWeight: 800,
            fontSize: 38,
            color: tokens.vz.prog4,
            textAlign: 'center',
          }}
        >
          What if everything worked together?
        </div>
      </div>
    </AbsoluteFill>
  );
};
