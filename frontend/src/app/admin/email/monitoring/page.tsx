import { permanentRedirect } from 'next/navigation';

// The old gateway monitoring page is now part of Messaging Suite (NovrSOC Mail Gateway source).
export default function Page() {
    permanentRedirect('/admin/email/messaging');
}
