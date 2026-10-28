// A tiny deterministic PRNG (mulberry32), seeded from a string. Every demo generator in this
// directory derives its random-looking numbers from a seed built from (org id, domain, index) —
// never Math.random() — so the same organisation always shows the same demo content across every
// screen and every reload. That's what "internally consistent" (the same CVE in both the findings
// list and the remediation task, the same incident id in both SecOps and the executive summary)
// actually requires: a stable function of identity, not a fresh roll each time.

function hashSeed(s: string): number {
    let h = 1779033703 ^ s.length;
    for (let i = 0; i < s.length; i++) {
        h = Math.imul(h ^ s.charCodeAt(i), 3432918353);
        h = (h << 13) | (h >>> 19);
    }
    return h >>> 0;
}

/** A seeded RNG instance — call .next() for a float in [0,1), or the helpers below. */
export function seededRng(seed: string) {
    let a = hashSeed(seed) || 1;
    const next = () => {
        a |= 0; a = (a + 0x6D2B79F5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    return {
        next,
        int: (min: number, max: number) => min + Math.floor(next() * (max - min + 1)),
        pick: <T,>(arr: readonly T[]): T => arr[Math.floor(next() * arr.length)],
        bool: (p = 0.5) => next() < p,
        /** A value that drifts slowly over real time within [min,max], so a chart doesn't look
         * frozen across repeated demo sessions without needing per-render randomness. */
        wave: (min: number, max: number, periodMs: number, phase: number) => {
            const t = (Date.now() / periodMs + phase) % 1;
            return min + (max - min) * (0.5 + 0.5 * Math.sin(2 * Math.PI * t));
        },
    };
}

export const seeded = <T,>(seed: string, build: (r: ReturnType<typeof seededRng>) => T): T => build(seededRng(seed));
