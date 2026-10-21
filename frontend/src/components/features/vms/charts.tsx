'use client';

// VMS charts (redesign, phase P20). Colours are the validated --vz-* tokens (globals.css), resolved
// for the active theme with useCssTokens because SVG attributes do not resolve CSS var(). Every
// chart has a text equivalent (aria-label summary, legend with values) and a tooltip; none animates
// its geometry (the wrapper fades in, only when motion is allowed). A chart with nothing to show
// says so instead of drawing an empty frame.

import type { ReactNode } from 'react';
import Link from 'next/link';
import { ResponsiveContainer, AreaChart, Area, BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip } from 'recharts';
import { Card, SectionTitle, Skeleton, Tip, useCssTokens } from './ui';
import { EmptyState, nf, fmtDay } from './kit';

export const TOKENS = [
    '--vz-sev-critical', '--vz-sev-high', '--vz-sev-medium', '--vz-sev-low', '--vz-sev-info',
    '--vz-prog-1', '--vz-prog-2', '--vz-prog-3', '--vz-prog-4', '--vz-neutral',
    '--vz-good', '--vz-warning', '--vz-serious', '--vz-critical', '--vz-cat-1', '--vz-cat-3',
    '--vz-grid', '--vz-axis', '--foreground-muted', '--card',
] as const;
export type Token = (typeof TOKENS)[number];
export interface Series { key: string; label: string; token: Token }

/** A titled card holding one chart, with loading and empty states. */
export function ChartCard({ title, hint, action, loading, empty, children, className = '', height = 220 }: {
    title: string; hint?: ReactNode; action?: ReactNode; loading?: boolean; empty?: { title: string; body?: ReactNode } | null; children: ReactNode; className?: string; height?: number;
}) {
    return (
        <Card className={`flex flex-col ${className}`}>
            <SectionTitle title={title} hint={typeof hint === 'string' ? hint : undefined} action={action} />
            {hint && typeof hint !== 'string' && <div className="-mt-3 mb-3 text-[11px] text-foreground-muted">{hint}</div>}
            {loading ? <Skeleton className="w-full" style={{ height }} />
                : empty ? <div style={{ minHeight: height }} className="flex items-center justify-center"><EmptyState compact title={empty.title} body={empty.body} /></div>
                : <div className="motion-safe:animate-[vzfade_400ms_ease-out]">{children}</div>}
        </Card>
    );
}

function ChartTooltip({ active, payload, label, labelFormat }: { active?: boolean; payload?: { name: string; value: number; color: string; dataKey: string }[]; label?: string; labelFormat?: (l: string) => string }) {
    if (!active || !payload?.length) return null;
    return (
        <div className="rounded-lg border border-border bg-card px-3 py-2 shadow-lg text-[11px] min-w-[140px]">
            <p className="font-semibold text-foreground mb-1">{label && labelFormat ? labelFormat(label) : label}</p>
            {[...payload].reverse().map((p) => (
                <p key={p.dataKey} className="flex items-center justify-between gap-4 text-foreground">
                    <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm" style={{ background: p.color }} />{p.name}</span>
                    <span className="font-bold tabular-nums">{p.value === null || p.value === undefined ? '—' : nf.format(p.value)}</span>
                </p>
            ))}
        </div>
    );
}

/** Daily series as stacked areas, stacked bars or lines. `data` rows are { day: 'YYYY-MM-DD', [series.key]: n }. */
export function TimeChart({ data, series, kind, height = 220, stacked = true, yMax, label }: {
    data: Record<string, unknown>[]; series: Series[]; kind: 'area' | 'bar' | 'line'; height?: number; stacked?: boolean; yMax?: number; label: string;
}) {
    const c = useCssTokens(TOKENS);
    const axis = { stroke: c['--vz-axis'], tick: { fill: c['--foreground-muted'], fontSize: 10 }, tickLine: false };
    const totals = series.map((s) => `${s.label} ${nf.format(data.reduce((n, r) => n + (Number(r[s.key]) || 0), 0))}`).join(', ');
    const common = { data, margin: { top: 8, right: 8, left: -18, bottom: 0 } };
    const grid = <CartesianGrid stroke={c['--vz-grid']} vertical={false} />;
    const x = <XAxis dataKey="day" {...axis} minTickGap={28} tickFormatter={(d: string) => fmtDay(d)} />;
    const y = <YAxis {...axis} allowDecimals={false} width={44} domain={yMax ? [0, yMax] : [0, 'auto']} />;
    const tip = <RTooltip content={<ChartTooltip labelFormat={fmtDay} />} cursor={kind === 'bar' ? { fill: c['--vz-grid'] } : { stroke: c['--vz-axis'] }} />;
    return (
        <div role="img" aria-label={`${label}. Totals over the period: ${totals}.`} style={{ height }}>
            <ResponsiveContainer width="100%" height="100%">
                {kind === 'area' ? (
                    <AreaChart {...common}>{grid}{x}{y}{tip}
                        {series.map((s) => <Area key={s.key} type="monotone" dataKey={s.key} name={s.label} stackId={stacked ? '1' : undefined} stroke={c[s.token]} strokeWidth={2} fill={c[s.token]} fillOpacity={0.32} isAnimationActive={false} />)}
                    </AreaChart>
                ) : kind === 'bar' ? (
                    <BarChart {...common} barCategoryGap="18%">{grid}{x}{y}{tip}
                        {series.map((s, i) => <Bar key={s.key} dataKey={s.key} name={s.label} stackId={stacked ? '1' : undefined} fill={c[s.token]} radius={stacked && i < series.length - 1 ? 0 : [3, 3, 0, 0]} isAnimationActive={false} />)}
                    </BarChart>
                ) : (
                    <LineChart {...common}>{grid}{x}{y}{tip}
                        {series.map((s) => <Line key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={c[s.token]} strokeWidth={2} dot={data.length < 3 ? { r: 3 } : false} connectNulls={false} isAnimationActive={false} />)}
                    </LineChart>
                )}
            </ResponsiveContainer>
        </div>
    );
}

export function Legend({ series }: { series: Series[] }) {
    return (
        <ul className="flex flex-wrap gap-x-4 gap-y-1 mt-3">
            {series.map((s) => <li key={s.key} className="flex items-center gap-1.5 text-[11px] text-foreground-muted"><span className="w-2.5 h-2.5 rounded-sm" style={{ background: `var(${s.token})` }} aria-hidden />{s.label}</li>)}
        </ul>
    );
}

export interface Slice { key: string; label: string; value: number; token: Token; href?: string }
/** Donut with the total in the middle and a legend that carries every value (and links, if given). */
export function Donut({ slices, centerLabel, label, size = 168 }: { slices: Slice[]; centerLabel: string; label: string; size?: number }) {
    const c = useCssTokens(TOKENS);
    const total = slices.reduce((n, s) => n + s.value, 0);
    const shown = slices.filter((s) => s.value > 0);
    return (
        <div className="flex flex-col items-center gap-4">
            <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`${label}: ${slices.map((s) => `${s.label} ${s.value}`).join(', ')}`}>
                <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                        <Pie data={shown} dataKey="value" nameKey="label" innerRadius="66%" outerRadius="100%" paddingAngle={shown.length > 1 ? 2 : 0} stroke={c['--card']} strokeWidth={2} isAnimationActive={false}>
                            {shown.map((s) => <Cell key={s.key} fill={c[s.token]} />)}
                        </Pie>
                        <RTooltip content={<ChartTooltip />} />
                    </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-2xl font-black text-foreground tabular-nums">{nf.format(total)}</span>
                    <span className="text-[10px] text-foreground-muted">{centerLabel}</span>
                </div>
            </div>
            <ul className="w-full space-y-0.5">
                {slices.map((s) => {
                    const row = (
                        <>
                            <span className="flex items-center gap-2 min-w-0"><span className="w-2.5 h-2.5 rounded-[3px] shrink-0" style={{ background: `var(${s.token})` }} aria-hidden /><span className="truncate">{s.label}</span></span>
                            <span className="flex items-baseline gap-2 tabular-nums"><span className="font-bold text-foreground">{nf.format(s.value)}</span><span className="text-[10px] text-foreground-muted w-8 text-right">{total ? `${Math.round((s.value / total) * 100)}%` : '—'}</span></span>
                        </>
                    );
                    return (
                        <li key={s.key}>
                            {s.href ? <Link href={s.href} className="flex items-center justify-between gap-3 text-xs text-foreground rounded-md px-1.5 py-1 -mx-1.5 hover:bg-card-muted">{row}</Link>
                                : <div className="flex items-center justify-between gap-3 text-xs text-foreground px-1.5 py-1 -mx-1.5">{row}</div>}
                        </li>
                    );
                })}
            </ul>
        </div>
    );
}

export interface BarItem { key: string; label: ReactNode; value: number; token?: Token; href?: string; note?: string }
/** Horizontal bars (HTML, so labels wrap and stay readable). Bars scale to the largest value. */
export function BarList({ items, label, max }: { items: BarItem[]; label: string; max?: number }) {
    const top = max ?? Math.max(1, ...items.map((i) => i.value));
    return (
        <ul className="space-y-2.5" aria-label={label}>
            {items.map((i) => {
                const inner = (
                    <>
                        <div className="flex items-center justify-between gap-3 text-xs mb-1">
                            <span className="text-foreground truncate">{i.label}</span>
                            <span className="font-bold tabular-nums text-foreground">{nf.format(i.value)}</span>
                        </div>
                        <Tip label={i.note ?? `${nf.format(i.value)}`} className="w-full">
                            <span className="block h-2 w-full rounded-full bg-card-muted overflow-hidden">
                                <span className="block h-full rounded-full" style={{ width: `${(i.value / top) * 100}%`, minWidth: i.value ? 4 : 0, background: `var(${i.token ?? '--vz-prog-3'})` }} />
                            </span>
                        </Tip>
                    </>
                );
                return <li key={i.key}>{i.href ? <Link href={i.href} className="block rounded-md hover:bg-card-muted/60 -mx-1.5 px-1.5 py-0.5">{inner}</Link> : inner}</li>;
            })}
        </ul>
    );
}
