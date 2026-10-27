import React from 'react';
import { tokens } from '../../lib/tokens';

/**
 * Same "SYNTHETIC DEMO DATA" convention used in VmsDashboardPrototype.tsx, extracted so every new
 * scene in this build uses the identical label/placement instead of re-inventing it.
 */
export const DemoDataBadge: React.FC<{ label?: string }> = ({ label = 'SYNTHETIC DEMO DATA' }) => (
  <div
    style={{
      position: 'absolute',
      bottom: 24,
      right: 32,
      fontFamily: 'JetBrains Mono',
      fontSize: 12,
      letterSpacing: '0.08em',
      color: tokens.surface.foregroundMuted,
      background: tokens.surface.cardMuted,
      border: `1px solid ${tokens.surface.border}`,
      borderRadius: 8,
      padding: '6px 12px',
      opacity: 0.9,
    }}
  >
    {label}
  </div>
);
