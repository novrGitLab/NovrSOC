// Single source of truth for scene order/durations. VOICEOVER_SCRIPT.md, STORYBOARD.md and the
// subtitle cues in subtitles.ts are all derived from these numbers — change here, not per-file.
export const FPS = 30;

export interface SceneDef {
  id: string;
  title: string;
  seconds: number;
}

// Durations match the approved brief exactly (sum = 300s / 9000 frames).
export const SCENES: SceneDef[] = [
  { id: 'challenge', title: 'The Cybersecurity Challenge', seconds: 35 },
  { id: 'introducing', title: 'Introducing NovrSOC', seconds: 30 },
  { id: 'pillars', title: 'Four Security Pillars', seconds: 80 },
  { id: 'ai-soar', title: 'AI, Automation and Security Intelligence', seconds: 45 },
  { id: 'decision-cycle', title: 'See → Prioritize → Act → Communicate', seconds: 35 },
  { id: 'integrations', title: 'Built to Connect, Not Replace', seconds: 30 },
  { id: 'trust', title: 'Trust, Compliance and Deployment', seconds: 25 },
  { id: 'closing', title: 'Cybernovr Brand and Closing', seconds: 20 },
];

export const sceneFrames = (s: SceneDef) => s.seconds * FPS;

export const TOTAL_FRAMES = SCENES.reduce((sum, s) => sum + sceneFrames(s), 0);

// Absolute start frame of each scene within the full composition.
export const sceneStartFrame = (id: string): number => {
  let acc = 0;
  for (const s of SCENES) {
    if (s.id === id) return acc;
    acc += sceneFrames(s);
  }
  throw new Error(`Unknown scene id: ${id}`);
};

// Four equal pillar sub-segments inside "pillars" (80s / 2400 frames -> 600 frames / 20s each).
export const PILLAR_IDS = ['vms', 'ti', 'cnii', 'secops'] as const;
export const PILLAR_SUB_FRAMES = sceneFrames(SCENES.find((s) => s.id === 'pillars')!) / PILLAR_IDS.length;
