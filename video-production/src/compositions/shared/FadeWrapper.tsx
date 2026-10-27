import React from 'react';
import { AbsoluteFill, interpolate, useCurrentFrame } from 'remotion';

/**
 * Wraps a scene's content with a short fade-from-black / fade-to-black at its own edges.
 * Scenes are placed back-to-back with no overlap (exact, deterministic durations matching the
 * approved script timing) — this is the "smooth transition" instead of a cross-dissolve, which
 * would require overlapping sequences and an extra dependency (@remotion/transitions) that isn't
 * needed for a dip-to-black treatment. Also makes the loop (scene 8 -> scene 1) symmetric.
 */
export const FadeWrapper: React.FC<{ durationInFrames: number; fadeFrames?: number; children: React.ReactNode }> = ({
  durationInFrames,
  fadeFrames = 12,
  children,
}) => {
  const frame = useCurrentFrame();
  const opacity = interpolate(
    frame,
    [0, fadeFrames, durationInFrames - fadeFrames, durationInFrames],
    [0, 1, 1, 0],
    { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' },
  );
  return (
    <AbsoluteFill style={{ background: '#000000' }}>
      <AbsoluteFill style={{ opacity }}>{children}</AbsoluteFill>
    </AbsoluteFill>
  );
};
