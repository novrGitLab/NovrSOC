import React from 'react';
import { Img, staticFile } from 'remotion';

/**
 * The real NovrSOC/Cybernovr wordmark, copied as-is from frontend/public/novrsoc.jpg (the same
 * asset the live app's shared Logo.tsx component renders) — not a recreated or invented logo.
 * Source image is 632x233 (~2.714:1); sized by height to keep its real aspect ratio.
 */
export const Logo: React.FC<{ height?: number; style?: React.CSSProperties }> = ({ height = 120, style }) => (
  <Img
    src={staticFile('novrsoc.jpg')}
    style={{ height, width: height * 2.714, objectFit: 'contain', ...style }}
  />
);
