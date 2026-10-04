import type { ReactNode } from 'react';
import { EmailSecurityShell } from '@/components/features/email-security/context';

// Shared shell for every Email Security page: organisation, overall status and setup progress,
// loaded once from the backend (see context.tsx).
export default function EmailSecurityLayout({ children }: { children: ReactNode }) {
    return <EmailSecurityShell>{children}</EmailSecurityShell>;
}
