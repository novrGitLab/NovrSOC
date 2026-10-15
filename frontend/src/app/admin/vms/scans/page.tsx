import { VmsScans } from '@/components/features/vms/VmsScans';
import { VmsSchedules } from '@/components/features/vms/VmsSchedules';

export default function Page() {
    return (
        <div className="space-y-6">
            <VmsScans />
            <VmsSchedules />
        </div>
    );
}
