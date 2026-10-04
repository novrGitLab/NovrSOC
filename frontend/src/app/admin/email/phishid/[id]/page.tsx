import { permanentRedirect } from 'next/navigation';

// Old investigation URL (/admin/email/phishid/<id>) — moved to /admin/email/phishid/investigate/<domain or id>.
export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    permanentRedirect(`/admin/email/phishid/investigate/${encodeURIComponent(id)}`);
}
