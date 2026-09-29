import { Suspense } from 'react';
import { MessagingSuite } from '@/components/features/email-security/MessagingSuite';

// Suspense: MessagingSuite reads the Microsoft 365 consent result from the query string.
export default function Page() {
    return (
        <Suspense>
            <MessagingSuite />
        </Suspense>
    );
}
