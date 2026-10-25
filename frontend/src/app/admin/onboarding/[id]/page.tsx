import { OnboardingWizard } from '@/components/features/OnboardingWizard';

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    return <OnboardingWizard orgId={id} />;
}
