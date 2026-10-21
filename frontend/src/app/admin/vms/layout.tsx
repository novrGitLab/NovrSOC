import { VmsShell } from '@/components/features/vms/VmsShell';

export default function VmsLayout({ children }: { children: React.ReactNode }) {
    return <VmsShell>{children}</VmsShell>;
}
