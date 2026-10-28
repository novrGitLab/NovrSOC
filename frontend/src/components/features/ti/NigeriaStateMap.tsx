'use client';

// The Nigeria state choropleth itself, extracted from TiMap.tsx (2026 redesign, Stage 4) so the
// dashboard's Nigeria map can reuse the exact same component instead of its own, separately
// maintained SVG (components/geo/NigeriaThreatMap.tsx + NigeriaMap2.tsx, retired). TiMap.tsx's
// own rendering is unchanged — it now calls this component instead of inlining the same markup.
//
// No coordinates, no attack counts: a state is shaded only from a real per-state count the
// caller supplies (hosted infrastructure or exposure, never an attack origin or target — see
// TiMap.tsx's header comment for what that count may and may not mean).
import { Info } from 'lucide-react';
import { NIGERIA_STATE_PATHS, NIGERIA_VIEWBOX } from './nigeriaPaths';

// The outline file spells it "Nassarawa"; the data uses the official "Nasarawa".
const stateKey = (name: string) => (name === 'Nassarawa' ? 'Nasarawa' : name);
const SHADES = ['var(--card-muted)', 'color-mix(in oklab, var(--vz-prog-1) 45%, var(--card))', 'var(--vz-prog-2)', 'var(--vz-prog-3)', 'var(--vz-prog-4)'];
/** Traffic-light severity shades (green/yellow/orange/red), already in the design system's token
 * set — same tokens used for status pills elsewhere — rather than the default intensity
 * progression above. Opt in with shades="severity" for a view that is literally about severity
 * (e.g. a threat heatmap), not a plain magnitude count. */
const SEVERITY_SHADES = ['var(--card-muted)', 'var(--vz-good)', 'var(--vz-warning)', 'var(--vz-serious)', 'var(--vz-critical)'];
const shade = (n: number, max: number, shades: string[]) => (n <= 0 ? shades[0] : shades[Math.min(4, 1 + Math.floor((n / Math.max(1, max)) * 3.999))]);

export function NigeriaStateMap({ counts, layer, selected, onSelect, countLabel, compact = false, shades = 'progression' }: {
    counts: Map<string, number>;
    /** Only used to word the accessible label for each state ("N hosted indicator(s)" / "N match(es)"). */
    layer: 'hosted' | 'exposure' | 'other';
    selected?: string | null;
    onSelect?: (state: string) => void;
    /** Overrides the default per-layer wording, e.g. "threats" for a non-TI count. */
    countLabel?: string;
    /** Smaller legend text for a tight dashboard card. */
    compact?: boolean;
    /** "severity" shades low/moderate/high/critical as green/yellow/orange/red instead of the
     * default purple intensity progression — for a view whose count IS a severity, not a plain
     * magnitude. */
    shades?: 'progression' | 'severity';
}) {
    const palette = shades === 'severity' ? SEVERITY_SHADES : SHADES;
    const max = Math.max(0, ...counts.values());
    const unit = countLabel ?? (layer === 'hosted' ? 'hosted indicator(s)' : layer === 'exposure' ? 'match(es)' : 'record(s)');
    return (
        <>
            <svg viewBox={NIGERIA_VIEWBOX} className="w-full h-auto max-h-[520px]" role="img" aria-label={`Nigeria map, by state`}>
                {NIGERIA_STATE_PATHS.map((p) => {
                    const name = stateKey(p.name);
                    const n = counts.get(name) ?? 0;
                    const active = selected === name;
                    return (
                        <path key={p.code} d={p.d} fill={shade(n, max, palette)} stroke={active ? 'var(--color-purple)' : 'var(--color-border)'} strokeWidth={active ? 3 : 1}
                            className={onSelect ? 'cursor-pointer outline-none focus-visible:[stroke:var(--color-purple)] focus-visible:[stroke-width:3px] hover:opacity-90' : undefined}
                            tabIndex={onSelect ? 0 : undefined} role={onSelect ? 'button' : undefined} aria-label={`${name}: ${n} ${unit}`}
                            onClick={onSelect ? () => onSelect(name) : undefined}
                            onKeyDown={onSelect ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(name); } } : undefined}>
                            <title>{`${name}: ${n}`}</title>
                        </path>
                    );
                })}
            </svg>
            <div className={`flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 ${compact ? 'text-[10px]' : 'text-[11px]'} text-foreground-muted`}>
                <span className="flex items-center gap-1.5"><span className="inline-block w-3 h-3 rounded-sm border border-border" style={{ background: palette[0] }} /> none</span>
                {shades === 'severity'
                    ? (['Low', 'Moderate', 'High', 'Critical'] as const).map((label, i) => <span key={label} className="flex items-center gap-1.5"><span className="inline-block w-3 h-3 rounded-sm" style={{ background: palette[i + 1] }} /> {label}</span>)
                    : palette.slice(1).map((c, i) => <span key={c} className="flex items-center gap-1.5"><span className="inline-block w-3 h-3 rounded-sm" style={{ background: c }} /> {i === 3 ? `up to ${max}` : ''}</span>)}
                {!compact && <span className="flex items-center gap-1"><Info className="w-3 h-3" aria-hidden /> Placed on a state only when the provider named it.</span>}
            </div>
        </>
    );
}
