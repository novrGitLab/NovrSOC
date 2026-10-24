import { redirect } from 'next/navigation';

// Moved into the Threat Intelligence module (P25); kept so existing links and bookmarks still work.
export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(await searchParams)) if (typeof v === 'string') q.set(k, v);
    const target = '/admin/ti/vulnerabilities';
    const extra = q.toString();
    redirect(extra ? `${target}${target.includes('?') ? '&' : '?'}${extra}` : target);
}
