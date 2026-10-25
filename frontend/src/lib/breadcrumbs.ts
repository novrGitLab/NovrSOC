// Meaningful breadcrumbs for the header (2026 redesign, Stage 1): "Section / Page" from the same
// data the sidebar already uses — config/nav.ts for most of the app, config/vmsSections.ts for
// the VMS module (its pages are reached through the VMS tab shell, not listed in nav.ts itself).
// Falls back to the last URL segment, humanized, when nothing matches — the previous behaviour —
// so an unlisted or dynamic route (an id) still shows something instead of nothing.
//
// The matching logic (breadcrumbFromSections) takes its data as plain parameters rather than
// importing config/nav.ts and config/vmsSections.ts itself, so it can be unit-tested with small
// fixture data (scripts/breadcrumbs.test.mjs) without transpiling those two files (which pull in
// lucide-react icon modules) just to exercise matching. breadcrumbFor() below is the one real
// call site uses, with the app's actual navigation data.
import { ADMIN_NAV, CLIENT_NAV } from '@/config/nav';
import { VMS_SECTIONS } from '@/config/vmsSections';

export interface Breadcrumb { section: string; page: string }
interface NavItemLike { href: string; label: string; match?: string[] }
interface NavSectionLike { section: string; groupLabel?: string; items: NavItemLike[] }
interface VmsPageLike { href: string; label: string }
interface VmsSectionLike { href: string; label: string; pages: VmsPageLike[] }

export function humanizeLastSegment(pathname: string): string {
    const last = pathname.split('/').filter(Boolean).pop() ?? '';
    return last.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

/** The best (section, item) match for `pathname`: an exact href first, then the longest `match` prefix. */
function findNavItem(sections: NavSectionLike[], pathname: string): { section: NavSectionLike; item: NavItemLike } | null {
    for (const section of sections) {
        const exact = section.items.find((i) => i.href === pathname);
        if (exact) return { section, item: exact };
    }
    let best: { section: NavSectionLike; item: NavItemLike; len: number } | null = null;
    for (const section of sections) {
        for (const item of section.items) {
            for (const prefix of item.match ?? []) {
                if (pathname.startsWith(prefix) && (!best || prefix.length > best.len)) best = { section, item, len: prefix.length };
            }
        }
    }
    return best ? { section: best.section, item: best.item } : null;
}

export function breadcrumbFromSections(pathname: string, navSections: NavSectionLike[], vmsSections: VmsSectionLike[]): Breadcrumb {
    if (pathname.startsWith('/admin/vms')) {
        const section = vmsSections.find((s) => s.pages.some((p) => p.href === pathname))
            ?? vmsSections.find((s) => pathname.startsWith(s.href) && s.href !== '/admin/vms');
        const page = section?.pages.find((p) => p.href === pathname);
        if (section) return { section: 'VMS', page: page?.label ?? section.label };
        return { section: 'VMS', page: humanizeLastSegment(pathname) };
    }
    const found = findNavItem(navSections, pathname);
    if (found) return { section: found.section.groupLabel ?? found.section.section, page: found.item.label };
    if (pathname.endsWith('/dashboard')) return { section: 'Overview', page: 'Dashboard' };
    return { section: '', page: humanizeLastSegment(pathname) };
}

export function breadcrumbFor(pathname: string): Breadcrumb {
    const sections = pathname.startsWith('/client') ? CLIENT_NAV : ADMIN_NAV;
    return breadcrumbFromSections(pathname, sections, VMS_SECTIONS);
}
