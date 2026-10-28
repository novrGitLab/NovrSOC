import React from 'react';

interface ChartWrapperProps {
    title: string;
    height?: string;
    children: React.ReactNode;
    /** False when the data behind this chart is known to be unavailable right now (a failed
     * fetch, not a quiet period) — showing a pulsing "Live" badge over an error would claim a
     * freshness the chart doesn't have. Defaults to true, matching every existing caller. */
    live?: boolean;
}

export const ChartWrapper = ({ title, height = "h-64", children, live = true }: ChartWrapperProps) => {
    return (
        <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between">
                <h3 className="font-bold text-foreground-muted text-xs tracking-wide uppercase">{title}</h3>
                {live ? (
                    <div className="flex items-center gap-1.5">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green opacity-60" />
                            <span className="relative inline-flex h-2 w-2 rounded-full bg-green" />
                        </span>
                        <span className="text-[10px] text-foreground-muted font-semibold">Live</span>
                    </div>
                ) : (
                    <span className="text-[10px] text-amber font-semibold">Unavailable</span>
                )}
            </div>
            <div className={`${height} w-full p-5 relative overflow-hidden bg-card`}>
                {children}
            </div>
        </div>
    );
};
