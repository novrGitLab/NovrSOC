import React from 'react';
import { tokens } from '../../lib/tokens';

export const PageHeader: React.FC<{
  title: string;
  description?: string;
  icon?: React.ReactNode;
  opacity?: number;
  translateY?: number;
}> = ({ title, description, icon, opacity = 1, translateY = 0 }) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        opacity,
        transform: `translateY(${translateY}px)`,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {icon && (
          <div
            style={{
              color: tokens.vz.prog4,
              display: 'flex',
              alignItems: 'center',
            }}
          >
            {icon}
          </div>
        )}
        <h1
          style={{
            fontFamily: 'Space Grotesk',
            fontWeight: 800,
            fontSize: 30,
            letterSpacing: '-0.02em',
            color: tokens.surface.foreground,
            margin: 0,
          }}
        >
          {title}
        </h1>
      </div>
      {description && (
        <p
          style={{
            fontFamily: 'Inter',
            fontSize: 15,
            color: tokens.surface.foregroundMuted,
            margin: 0,
            maxWidth: 820,
            lineHeight: 1.5,
          }}
        >
          {description}
        </p>
      )}
    </div>
  );
};
