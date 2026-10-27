import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { tokens } from '../../lib/tokens';
import { ALL_CUES } from '../../lib/subtitles';

/**
 * Burned-in captions for the whole composition. Rendered once at the ConferenceVideo root (not
 * inside any per-scene <Sequence>) so `useCurrentFrame()` here is the GLOBAL frame and lines up
 * directly with the absolute frames in ALL_CUES. There is no narration audio in this render —
 * these captions are the planned-timing stand-in per the brief, ready to be kept once real
 * voiceover audio is added later (see docs/RENDER_GUIDE.md).
 */
export const Subtitle: React.FC = () => {
  const frame = useCurrentFrame();
  const cue = ALL_CUES.find((c) => frame >= c.startFrame && frame < c.endFrame);
  if (!cue) return null;

  const local = frame - cue.startFrame;
  const span = cue.endFrame - cue.startFrame;
  const opacity = interpolate(
    local,
    [0, 4, Math.max(5, span - 4), span],
    [0, 1, 1, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );

  return (
    <div
      style={{
        position: 'absolute',
        left: 0,
        right: 0,
        bottom: 64,
        display: 'flex',
        justifyContent: 'center',
        pointerEvents: 'none',
      }}
    >
      <div
        style={{
          opacity,
          maxWidth: 1240,
          padding: '12px 28px',
          borderRadius: 12,
          background: 'rgba(13, 15, 26, 0.78)',
          border: `1px solid ${tokens.surface.border}`,
          fontFamily: 'Inter',
          fontWeight: 500,
          fontSize: 26,
          lineHeight: 1.4,
          color: tokens.surface.foreground,
          textAlign: 'center',
        }}
      >
        {cue.text}
      </div>
    </div>
  );
};
