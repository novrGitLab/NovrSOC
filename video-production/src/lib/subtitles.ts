// Canonical narration text + burned-in subtitle timing. This is the single source of truth for
// both the on-screen captions AND docs/VOICEOVER_SCRIPT.md's timestamps — the script doc is a
// human-readable transcription of exactly these lines/frames, not an independent document, so the
// two can never drift out of sync. No narration audio exists yet (confirmed absent from the repo);
// these cues drive burned-in captions on an otherwise silent render.
import { FPS, PILLAR_SUB_FRAMES, SCENES, sceneFrames, sceneStartFrame } from './timing';

export interface Cue {
  startFrame: number; // absolute, in the full 9000-frame composition
  endFrame: number;
  text: string;
}

const wordCount = (s: string) => s.trim().split(/\s+/).length;

// Lays `lines` out back-to-back inside a [frameOffset, frameOffset + durationFrames) window,
// proportional to each line's word count, with a small gap after each line for readability.
function layout(frameOffset: number, durationFrames: number, lines: string[], gapFrames = 5): Cue[] {
  const counts = lines.map(wordCount);
  const totalWords = counts.reduce((a, b) => a + b, 0);
  const usable = durationFrames - gapFrames * lines.length;
  let cursor = frameOffset;
  const cues: Cue[] = [];
  for (let i = 0; i < lines.length; i++) {
    const dur = Math.round((counts[i] / totalWords) * usable);
    const start = cursor;
    const end = start + dur;
    cues.push({ startFrame: start, endFrame: end, text: lines[i] });
    cursor = end + gapFrames;
  }
  return cues;
}

// --- Per-scene narration lines (verbatim source for VOICEOVER_SCRIPT.md) ---

export const SCRIPT_LINES: Record<string, string[]> = {
  challenge: [
    'Every day, security teams face a flood of signals,',
    'from firewalls, endpoint sensors, cloud platforms and threat feeds.',
    'Each tool sees a piece of the picture — none sees the whole one.',
    'Alerts pile up faster than anyone can review them.',
    'Context gets lost between tools, and between teams.',
    'Disconnected tools. Fragmented intelligence. Delayed response.',
    "What if everything worked together — what if one platform could see what all of them see, at once?",
  ],
  introducing: [
    'This is NovrSOC — a unified cybersecurity operations platform, built in Nigeria by Cybernovr.',
    'It brings vulnerability management, threat intelligence, security operations and compliance visibility into a single connected view.',
    'One platform. Connected security.',
    'Its workflow follows four simple steps: see, prioritize, act, and communicate —',
    'turning scattered signals into decisions your organization can trust.',
  ],
  'pillars-vms': [
    'NovrSOC brings four core security capabilities into one connected view.',
    'Vulnerability Management scores every exposure using industry-standard CVSS severity, known exploited vulnerabilities, and real-world exploit probability —',
    'then prioritizes it by urgency. Active scanning only runs after a named person in your organization formally authorizes it.',
  ],
  'pillars-ti': [
    'Threat Intelligence and Exposure draws from multiple external sources — including MISP, GreyNoise and RIPEstat —',
    "to show what's actually being observed outside your perimeter, not just what's reported inside it.",
  ],
  'pillars-cnii': [
    "CNII Monitoring extends that same visibility into Nigeria's critical national infrastructure sectors,",
    'tracking organizations, assets and findings within a national oversight structure.',
  ],
  'pillars-secops': [
    'And Security Operations brings alerts, investigations and incidents into a single workflow —',
    'from the moment a signal is detected, through triage and response, to resolution and reporting.',
  ],
  'ai-soar': [
    'Supporting all four pillars is an AI security analyst —',
    "grounded in your organization's own data, producing draft summaries, explanations and recommendations for alerts, cases and findings.",
    'Every output is a draft. A human analyst reviews and approves it before anything is finalized — the AI never takes action on its own.',
    'Threat intelligence is enriched automatically from multiple sources, and workflow automation helps route and accelerate response tasks.',
    'Email Security protects against phishing, spoofing and domain abuse with real DMARC and messaging-security monitoring.',
    'Brand monitoring adds a lighter, complementary layer of visibility.',
    'None of this replaces human judgment. It supports it.',
  ],
  'decision-cycle': [
    'Every capability in NovrSOC follows the same cycle.',
    'See — understand your assets, your exposures, and the signals coming from across your environment.',
    'Prioritize — identify which risks actually matter most right now, ranked by real severity and real-world exploitation, not guesswork.',
    "Act — coordinate investigation, remediation and response, with approvals where they're needed.",
    'Communicate — turn all of that work into clear reports, evidence and insight your organization can act on.',
  ],
  integrations: [
    "NovrSOC doesn't replace the security tools you already run — it connects them.",
    "It's built to work alongside firewalls, endpoint detection and response, SIEM platforms, network detection, cloud security, identity systems, and external threat intelligence —",
    'with IT service management and industrial control environments as conceptual integration targets.',
    'Connect what you have. Unify what you see.',
  ],
  trust: [
    'Access is role-based, from analyst to executive.',
    "Every organization's data is logically separated, with audit trails recording who did what, and when.",
    'NovrSOC is designed with Nigerian regulatory frameworks in mind, and runs as a cloud-native platform with Nigeria-based hosting options —',
    'security built around how your organization actually operates.',
  ],
  closing: [
    'Built in Nigeria, for security teams everywhere.',
    'Designed for connected security operations.',
    'NovrSOC. See. Prioritize. Act. Communicate.',
    'One platform. Connected security. Confident decisions.',
    'This is NovrSOC — powered by Cybernovr.',
  ],
};

export const TOTAL_WORDS = Object.values(SCRIPT_LINES)
  .flat()
  .reduce((sum, line) => sum + wordCount(line), 0);

// --- Build absolute-frame cues ---

const pillarsStart = sceneStartFrame('pillars');
const pillarSegmentOffset: Record<string, number> = {
  'pillars-vms': pillarsStart + 0 * PILLAR_SUB_FRAMES,
  'pillars-ti': pillarsStart + 1 * PILLAR_SUB_FRAMES,
  'pillars-cnii': pillarsStart + 2 * PILLAR_SUB_FRAMES,
  'pillars-secops': pillarsStart + 3 * PILLAR_SUB_FRAMES,
};

export const ALL_CUES: Cue[] = [
  ...layout(sceneStartFrame('challenge'), sceneFrames(SCENES.find((s) => s.id === 'challenge')!), SCRIPT_LINES.challenge),
  ...layout(sceneStartFrame('introducing'), sceneFrames(SCENES.find((s) => s.id === 'introducing')!), SCRIPT_LINES.introducing),
  ...layout(pillarSegmentOffset['pillars-vms'], PILLAR_SUB_FRAMES, SCRIPT_LINES['pillars-vms']),
  ...layout(pillarSegmentOffset['pillars-ti'], PILLAR_SUB_FRAMES, SCRIPT_LINES['pillars-ti']),
  ...layout(pillarSegmentOffset['pillars-cnii'], PILLAR_SUB_FRAMES, SCRIPT_LINES['pillars-cnii']),
  ...layout(pillarSegmentOffset['pillars-secops'], PILLAR_SUB_FRAMES, SCRIPT_LINES['pillars-secops']),
  ...layout(sceneStartFrame('ai-soar'), sceneFrames(SCENES.find((s) => s.id === 'ai-soar')!), SCRIPT_LINES['ai-soar']),
  ...layout(sceneStartFrame('decision-cycle'), sceneFrames(SCENES.find((s) => s.id === 'decision-cycle')!), SCRIPT_LINES['decision-cycle']),
  ...layout(sceneStartFrame('integrations'), sceneFrames(SCENES.find((s) => s.id === 'integrations')!), SCRIPT_LINES.integrations),
  ...layout(sceneStartFrame('trust'), sceneFrames(SCENES.find((s) => s.id === 'trust')!), SCRIPT_LINES.trust),
  ...layout(sceneStartFrame('closing'), sceneFrames(SCENES.find((s) => s.id === 'closing')!), SCRIPT_LINES.closing),
];
