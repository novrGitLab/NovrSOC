import React from 'react';
import { Composition } from 'remotion';
import { loadFont as loadSpaceGrotesk } from '@remotion/google-fonts/SpaceGrotesk';
import { loadFont as loadInter } from '@remotion/google-fonts/Inter';
import { loadFont as loadJetBrainsMono } from '@remotion/google-fonts/JetBrainsMono';
import { VmsDashboardPrototype } from './compositions/VmsDashboardPrototype';

// Same three families the real app loads via next/font/google in app/layout.tsx.
loadSpaceGrotesk();
loadInter();
loadJetBrainsMono();

const FPS = 30;
const DURATION_IN_FRAMES = 390; // 13s prototype

export const Root: React.FC = () => {
  return (
    <>
      <Composition
        id="VmsDashboardPrototype"
        component={VmsDashboardPrototype}
        durationInFrames={DURATION_IN_FRAMES}
        fps={FPS}
        width={1920}
        height={1080}
      />
    </>
  );
};
