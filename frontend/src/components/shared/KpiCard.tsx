import type { LucideIcon } from 'lucide-react';

// Moved here from the deleted data/mockData.ts (2026-10 cleanup).
export interface MetricItem {
    value: string;
    trend: string;
    type: 'blue' | 'purple' | 'orange' | 'red' | 'green';
    label: string;
}

const borderAccent: Record<string, string> = {
    blue:   'border-l-blue',
    purple: 'border-l-purple',
    orange: 'border-l-orange',
    red:    'border-l-red',
    green:  'border-l-green',
};

function trendClasses(trend?: string) {
    if (!trend) return 'text-foreground-muted bg-card-muted border-border';
    if (trend.startsWith('+')) return 'text-blue bg-blue/10 border-blue/30';
    if (trend.startsWith('-')) return 'text-red bg-red/10 border-red/30';
    return 'text-foreground-muted bg-card-muted border-border';
}

export interface KpiCardProps extends MetricItem {
    icon?: LucideIcon;
    subValue?: string;
}

export const KpiCard = ({ label, value, trend, type, icon: Icon, subValue }: KpiCardProps) => {
    const accent = borderAccent[type] ?? borderAccent.blue;
    return (
        <div className={`bg-card rounded-xl border border-border shadow-sm hover:shadow-md transition-all duration-200 overflow-hidden cursor-default border-l-4 ${accent}`}>
            <div className="p-5">
                <div className="flex items-start justify-between gap-2 mb-3">
                    <p className="text-sm text-foreground-muted font-medium leading-snug flex items-center gap-1.5">
                        {Icon && <Icon size={14} className="text-foreground-muted flex-shrink-0" />}
                        {label}
                    </p>
                    {trend && (
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border whitespace-nowrap flex-shrink-0 ${trendClasses(trend)}`}>
                            {trend.startsWith('+') ? '↑ ' : trend.startsWith('-') ? '↓ ' : ''}{trend}
                        </span>
                    )}
                </div>
                <p className="text-2xl font-bold text-foreground tracking-tight leading-none">{value}</p>
                {subValue && <p className="text-[10px] text-foreground-muted mt-1.5">{subValue}</p>}
            </div>
        </div>
    );
};
