'use client';

import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { feature } from 'topojson-client';
import type { Topology, GeometryCollection } from 'topojson-specification';
import type { Feature, Geometry } from 'geojson';
import { apiUrl, apiFetch } from '@/lib/api';

// Flat Natural Earth world map, replacing the Three.js globe (components/geo/WorldGlobe.tsx),
// which rendered a hardcoded attack list (China 134, Russia 78, …) rather than real data.
//
// Data is GET /api/threats/global-map — a Wazuh indexer aggregation of alert source countries
// over the last 7 days. Countries are matched on ISO-3166 NUMERIC codes because that's what
// world-atlas keys its topojson features on; the backend returns `numericCode` per country for
// exactly this reason, so this component never has to guess a mapping.

interface CountryThreat {
    country: string;
    countryCode: string;
    numericCode: string | null;
    threats: number;
    threatType: string;
}

interface TooltipState {
    name: string;
    count: number;
    x: number;
    y: number;
}

const NIGERIA_NUMERIC = '566';
const WORLD_ATLAS_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

export function GlobalThreatMap() {
    const svgRef = useRef<SVGSVGElement>(null);
    const wrapRef = useRef<HTMLDivElement>(null);
    const [threats, setThreats] = useState<CountryThreat[]>([]);
    const [tooltip, setTooltip] = useState<TooltipState | null>(null);
    const [loading, setLoading] = useState(true);
    const [mapError, setMapError] = useState<string | null>(null);
    // Backend explains an empty map rather than leaving it silently blank — e.g. alerts exist
    // but none are geolocated, which is a Wazuh GeoIP config issue, not a missing feature.
    const [diagnostic, setDiagnostic] = useState<string | null>(null);
    // 'greynoise' = internet-wide malicious scanning origins; 'wazuh' = alert sources seen by
    // this deployment's own monitored endpoints. The two answer different questions, so the
    // subtitle and attribution below say which one is on screen.
    const [source, setSource] = useState<string | null>(null);
    // Every source that actually reported for this response, so attribution lists all of them
    // rather than only the primary one.
    const [sources, setSources] = useState<string[]>([]);

    useEffect(() => {
        let cancelled = false;
        apiFetch(apiUrl('/api/threats/global-map'), { cache: 'no-store', signal: AbortSignal.timeout(15000) })
            .then((r) => r.json())
            .then((data) => {
                if (cancelled) return;
                setThreats(Array.isArray(data?.countries) ? data.countries : []);
                setDiagnostic(typeof data?.diagnostic === 'string' ? data.diagnostic : null);
                setSource(typeof data?.source === 'string' ? data.source : null);
                setSources(Array.isArray(data?.sources) ? data.sources.filter((s: unknown): s is string => typeof s === 'string') : []);
            })
            .catch(() => { if (!cancelled) setThreats([]); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, []);

    useEffect(() => {
        const svgEl = svgRef.current;
        const wrapEl = wrapRef.current;
        if (!svgEl || !wrapEl) return;

        let cancelled = false;

        const render = (world: Topology) => {
            if (cancelled || !svgRef.current) return;
            const width = wrapEl.clientWidth || 800;
            const height = wrapEl.clientHeight || 400;

            const svg = d3.select(svgRef.current);
            svg.selectAll('*').remove();
            svg.attr('viewBox', `0 0 ${width} ${height}`);

            const projection = d3.geoNaturalEarth1().scale(width / 6.2).translate([width / 2, height / 2]);
            const pathGenerator = d3.geoPath(projection);

            const countries = feature(world, world.objects.countries as GeometryCollection) as unknown as {
                features: Array<Feature<Geometry, { name?: string }> & { id?: string | number }>;
            };

            // Keyed on the numeric code the backend supplies, padded to 3 digits the same way
            // world-atlas ids are.
            const threatByNumeric = new Map<string, CountryThreat>();
            for (const t of threats) {
                if (t.numericCode) threatByNumeric.set(String(t.numericCode).padStart(3, '0'), t);
            }
            const maxThreats = Math.max(...threats.map((t) => t.threats), 1);
            const colorScale = d3.scaleSequential<string>().domain([0, maxThreats]).interpolator(d3.interpolateRgb('#FFE0D6', '#CC2B2B'));

            svg.append('g')
                .selectAll('path')
                .data(countries.features)
                .join('path')
                .attr('d', (d) => pathGenerator(d) ?? '')
                .attr('fill', (d) => {
                    const code = String(d.id ?? '').padStart(3, '0');
                    if (code === NIGERIA_NUMERIC) return '#520385'; // home tenant, always distinct
                    const hit = threatByNumeric.get(code);
                    return hit && hit.threats > 0 ? colorScale(hit.threats) : '#EEF0F6';
                })
                .attr('stroke', '#FFFFFF')
                .attr('stroke-width', (d) => (String(d.id ?? '').padStart(3, '0') === NIGERIA_NUMERIC ? 1.5 : 0.5))
                .style('cursor', 'pointer')
                .on('mousemove', function (event: MouseEvent, d) {
                    const code = String(d.id ?? '').padStart(3, '0');
                    const hit = threatByNumeric.get(code);
                    const name = hit?.country ?? d.properties?.name ?? 'Unknown';
                    const [x, y] = d3.pointer(event, wrapEl);
                    d3.select(this).attr('opacity', 0.75);
                    setTooltip({ name, count: hit?.threats ?? 0, x, y });
                })
                .on('mouseout', function () {
                    d3.select(this).attr('opacity', 1);
                    setTooltip(null);
                });

            // Animated attack flows from the top origins to Nigeria.
            //
            // Origins and their positions both come from real data, never a fixed list: the
            // countries are the top entries of the same `threats` response the choropleth and
            // the "Top Threat Origins" row below are drawn from, and each one's position is the
            // geographic centroid of its actual topojson feature (d3.geoCentroid). A hardcoded
            // origin list with hand-typed lat/lng is exactly what this component was built to
            // get away from — see the header comment on the globe it replaced — and it would
            // also drift silently the moment the backend's top origins changed.
            const centroidByNumeric = new Map<string, [number, number]>();
            for (const f of countries.features) {
                centroidByNumeric.set(String(f.id ?? '').padStart(3, '0'), d3.geoCentroid(f));
            }

            const nigeriaCentroid = centroidByNumeric.get(NIGERIA_NUMERIC);
            const destination = nigeriaCentroid ? projection(nigeriaCentroid) : null;

            if (destination) {
                const origins = threats
                    .filter((t) => t.numericCode && String(t.numericCode).padStart(3, '0') !== NIGERIA_NUMERIC && t.threats > 0)
                    .slice(0, 5);

                const flowLayer = svg.append('g').attr('pointer-events', 'none');

                origins.forEach((origin, i) => {
                    const centroid = centroidByNumeric.get(String(origin.numericCode).padStart(3, '0'));
                    const src = centroid ? projection(centroid) : null;
                    if (!src) return;

                    // Quadratic curve whose control point is lifted perpendicular to the
                    // source→destination line, scaled to the span. A fixed vertical offset
                    // flattens out on short hops and overshoots the viewBox on long ones.
                    const [sx, sy] = src;
                    const [dx, dy] = destination;
                    const span = Math.hypot(dx - sx, dy - sy);
                    const lift = Math.min(span * 0.3, height * 0.4);
                    const cx = (sx + dx) / 2;
                    const cy = (sy + dy) / 2 - lift;

                    const path = flowLayer
                        .append('path')
                        .attr('d', `M${sx},${sy} Q${cx},${cy} ${dx},${dy}`)
                        .attr('fill', 'none')
                        .attr('stroke', '#CC2B2B')
                        .attr('stroke-width', 1.25)
                        .attr('stroke-linecap', 'round')
                        .attr('opacity', 0.55);

                    const node = path.node();
                    if (!node) return;
                    const totalLength = node.getTotalLength() || 200;

                    const run = (selection: d3.Selection<SVGPathElement, unknown, null, undefined>, delay: number) => {
                        selection
                            .attr('stroke-dasharray', `${totalLength} ${totalLength}`)
                            .attr('stroke-dashoffset', totalLength)
                            .transition()
                            .duration(2000)
                            .delay(delay)
                            .ease(d3.easeLinear)
                            .attr('stroke-dashoffset', 0)
                            .on('end', function () {
                                run(d3.select(this), 1000);
                            });
                    };
                    run(path, i * 400);
                });

                // Nigeria end-point marker, so the convergence point reads as the target.
                flowLayer
                    .append('circle')
                    .attr('cx', destination[0])
                    .attr('cy', destination[1])
                    .attr('r', 3.5)
                    .attr('fill', '#520385')
                    .attr('stroke', '#FFFFFF')
                    .attr('stroke-width', 1.5);
            }
        };

        fetch(WORLD_ATLAS_URL)
            .then((r) => {
                if (!r.ok) throw new Error(`world-atlas returned HTTP ${r.status}`);
                return r.json();
            })
            .then((world: Topology) => render(world))
            .catch((err) => { if (!cancelled) setMapError(err instanceof Error ? err.message : 'Could not load map geometry'); });

        // Re-render on resize so the projection matches the container instead of stretching.
        const observer = new ResizeObserver(() => {
            fetch(WORLD_ATLAS_URL).then((r) => r.json()).then((world: Topology) => render(world)).catch(() => {});
        });
        observer.observe(wrapEl);

        return () => { cancelled = true; observer.disconnect(); };
    }, [threats]);

    return (
        <div className="bg-card border border-border rounded-2xl p-5">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                <div>
                    <h3 className="font-bold text-sm text-foreground">Global Threat Map</h3>
                    <p className="text-[10px] text-foreground-muted">
                        {source === 'greynoise'
                            ? 'Live malicious scanning origins, internet-wide — Nigeria highlighted'
                            : 'Alert source countries seen by monitored endpoints — Nigeria highlighted'}
                    </p>
                </div>
                <div className="flex items-center gap-3 flex-wrap">
                    {[
                        { label: 'No data', color: '#EEF0F6' },
                        { label: 'Low', color: '#FFE0D6' },
                        { label: 'High', color: '#CC2B2B' },
                        { label: 'Nigeria', color: '#520385' },
                    ].map((l) => (
                        <div key={l.label} className="flex items-center gap-1.5">
                            <div className="w-3 h-3 rounded-sm border border-border" style={{ background: l.color }} />
                            <span className="text-[9px] text-foreground-muted">{l.label}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div ref={wrapRef} className="relative w-full h-[400px]">
                {loading && (
                    <div className="absolute inset-0 flex items-center justify-center z-10">
                        <div className="text-xs text-foreground-muted">Loading threat map…</div>
                    </div>
                )}
                {mapError && (
                    <div className="absolute inset-0 flex items-center justify-center z-10">
                        <div className="text-xs text-foreground-muted text-center px-6">Map geometry unavailable ({mapError}). Threat counts are still listed below.</div>
                    </div>
                )}
                <svg ref={svgRef} className="w-full h-full" preserveAspectRatio="xMidYMid meet" />

                {/* Only claim flows are drawn when there is actually something to draw them
                    from — with no geolocated origins the map is a plain choropleth. */}
                {!loading && !mapError && threats.length > 0 && (
                    <div className="absolute bottom-0 left-0 right-0 flex items-center justify-between gap-3 text-[10px] text-foreground-muted pointer-events-none">
                        <span>Attack flows to Nigeria from the top {Math.min(threats.length, 5)} threat origins</span>
                    </div>
                )}

                {tooltip && (
                    <div
                        className="absolute bg-card border border-border rounded-lg p-2 shadow-lg pointer-events-none z-20 text-xs"
                        style={{ left: Math.min(tooltip.x + 10, (wrapRef.current?.clientWidth ?? 800) - 140), top: Math.max(tooltip.y - 34, 0) }}
                    >
                        <div className="font-bold text-foreground">{tooltip.name}</div>
                        <div className="text-foreground-muted">{tooltip.count.toLocaleString()} alert{tooltip.count === 1 ? '' : 's'}</div>
                    </div>
                )}
            </div>

            <div className="mt-4 pt-4 border-t border-border">
                <div className="text-[10px] text-foreground-muted uppercase tracking-wider mb-2">Top Threat Origins</div>
                {loading ? (
                    <div className="grid grid-cols-5 gap-2">
                        {Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-10 bg-card-muted rounded animate-pulse" />)}
                    </div>
                ) : threats.length === 0 ? (
                    <p className="text-[11px] text-foreground-muted">
                        {diagnostic ?? 'No geolocated alerts in the last 7 days — the indexer has nothing with a source country to plot yet.'}
                    </p>
                ) : (
                    <div className="grid grid-cols-5 gap-2">
                        {threats.slice(0, 5).map((t) => (
                            <div key={t.countryCode} className="text-center">
                                <div className="text-lg font-black text-red">{t.threats.toLocaleString()}</div>
                                <div className="text-[9px] text-foreground-muted truncate" title={t.country}>{t.country}</div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Lists every source that reported, not just the primary one. Names come from
                    the API's `sources` array so this can't drift out of step with what actually
                    contributed. */}
                {sources.length > 0 && (
                    <div className="text-[9px] text-foreground-muted mt-2 text-right">
                        Powered by{' '}
                        {sources
                            .map((s) =>
                                s === 'greynoise' ? 'GreyNoise Intelligence'
                                    : s === 'wazuh' ? 'Wazuh'
                                        : s === 'circl' ? 'CIRCL OSINT'
                                            : s
                            )
                            .join(' + ')}
                    </div>
                )}
            </div>
        </div>
    );
}

export default GlobalThreatMap;
