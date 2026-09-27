import { SecurityAssessmentAdmin } from '@/components/features/SecurityAssessmentAdmin';
import { TeamPresenceWidget } from '@/components/features/TeamPresence';

export default function Page() {
    return <SecurityAssessmentAdmin presence={<TeamPresenceWidget />} />;
}
