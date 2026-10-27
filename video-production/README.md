# NovrSOC — Conference Booth Video (Remotion)

Standalone Remotion/React/TypeScript project. Does not depend on or modify `frontend/` or
`backend/`. See [`docs/CODEBASE_AUDIT.md`](docs/CODEBASE_AUDIT.md) for the audit this was built
from (implementation status per feature, real design tokens, component inventory).

## Status

Prototype only: one composition, `VmsDashboardPrototype` (1920x1080, 30fps, 13s), demonstrating
the empty-to-populated dashboard animation using the real app's dark theme tokens and VMS Dashboard
KPI set, with clearly labeled synthetic data. The full 8-scene, ~5-minute video is not built yet —
pending approval and the narration script (not found in the repo; see audit §3).

## Setup

```bash
npm install
```

## Preview (interactive studio)

```bash
npm run preview
```

## Render to MP4

```bash
npm run render -- VmsDashboardPrototype out/vms-dashboard-prototype.mp4
```

## Render a still frame (quick sanity check, faster than a full render)

```bash
npm run still -- VmsDashboardPrototype out/still.png --frame=200
```

## List compositions

```bash
npm run compositions
```

## Project structure

```
src/
  index.ts                         entry point, registers Root
  Root.tsx                         composition registry + font loading
  lib/tokens.ts                    design tokens ported from frontend/src/app/globals.css
  compositions/
    VmsDashboardPrototype.tsx      the prototype composition
    shared/
      PageHeader.tsx               mirrors features/vms/kit.tsx PageHeader
      KpiCard.tsx                  mirrors features/vms/kit.tsx KpiCard (frame-driven count-up)
      SeverityDonut.tsx            mirrors features/vms/charts.tsx severity donut
      Sidebar.tsx                  mirrors components/layout/Sidebar.tsx nav groups
```

## Determinism

Animations are driven entirely by `useCurrentFrame()` / `interpolate()` / frame math — no
`Math.random()`, no wall-clock reads, no network calls at render time. Re-rendering the same
composition produces byte-identical frames.
