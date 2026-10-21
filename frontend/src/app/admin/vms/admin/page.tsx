import { redirect } from 'next/navigation';

// Moved in the VMS redesign (P20); kept so existing links and bookmarks still work.
export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(await searchParams)) if (typeof v === 'string') q.set(k, v);
    const target = '/admin/vms/operations';
    const extra = q.toString();
    redirect(extra ? `${target}${target.includes('?') ? '&' : '?'}${extra}` : target);
}
