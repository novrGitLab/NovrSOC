'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

// Single-series SLA compliance line (%, 0–100). One hue (brand blue), 2px line, visible point
// markers because the series is sparse, gaps where a month had no resolved cases — a gap is
// "not measured", never plotted as 0. The chart title names the series, so no legend box.

export interface SlaPoint { month: string; sla_rate: number | null; resolved: number }

const BLUE = '#2B3BCC';

function SlaTooltip({ active, payload }: { active?: boolean; payload?: { payload: SlaPoint }[] }) {
    if (!active || !payload?.length) return null;
    const p = payload[0].payload;
    return (
        <div className="bg-card border border-border rounded-lg px-3 py-2 shadow-md text-xs">
            <p className="font-bold text-foreground">{p.month}</p>
            <p className="text-foreground">{p.sla_rate === null ? 'No resolved cases' : `${p.sla_rate}% within SLA`}</p>
            <p className="text-foreground-muted">{p.resolved} case{p.resolved === 1 ? '' : 's'} resolved</p>
        </div>
    );
}

export function SlaTrendChart({ data, height = 220 }: { data: SlaPoint[]; height?: number }) {
    const measured = data.filter((d) => d.sla_rate !== null).length;
    return (
        <div>
            {measured === 0 ? (
                <div style={{ height }} className="flex items-center justify-center border border-dashed border-border rounded-lg">
                    <p className="text-[11px] text-foreground-muted text-center px-4">No cases resolved in these six months yet — nothing to plot.</p>
                </div>
            ) : (
                <div style={{ height }} role="img" aria-label={`SLA compliance by month: ${data.map((d) => `${d.month} ${d.sla_rate === null ? 'no data' : `${d.sla_rate}%`}`).join(', ')}`}>
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={data} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                            <CartesianGrid vertical={false} stroke="currentColor" strokeOpacity={0.08} />
                            <XAxis dataKey="month" tickLine={false} axisLine={false} tick={{ fontSize: 10, fill: '#7A8099' }} />
                            <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tickLine={false} axisLine={false} tick={{ fontSize: 10, fill: '#7A8099' }} unit="%" />
                            <Tooltip content={<SlaTooltip />} cursor={{ stroke: '#7A8099', strokeOpacity: 0.4, strokeWidth: 1 }} />
                            <Line type="monotone" dataKey="sla_rate" stroke={BLUE} strokeWidth={2} connectNulls={false} isAnimationActive={false}
                                dot={{ r: 4, fill: BLUE, stroke: 'var(--color-card, #fff)', strokeWidth: 2 }} activeDot={{ r: 5, fill: BLUE, stroke: 'var(--color-card, #fff)', strokeWidth: 2 }} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            )}
            {/* Table view of the same data. */}
            <details className="mt-2">
                <summary className="text-[10px] text-foreground-muted cursor-pointer">Show as table</summary>
                <table className="w-full text-[11px] mt-1.5">
                    <thead><tr className="text-left text-foreground-muted"><th className="font-bold py-1">Month</th><th className="font-bold">Within SLA</th><th className="font-bold">Resolved</th></tr></thead>
                    <tbody>
                        {data.map((d) => (
                            <tr key={d.month} className="border-t border-border/60">
                                <td className="py-1 text-foreground">{d.month}</td>
                                <td className="text-foreground">{d.sla_rate === null ? '—' : `${d.sla_rate}%`}</td>
                                <td className="text-foreground-muted">{d.resolved}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </details>
        </div>
    );
}
