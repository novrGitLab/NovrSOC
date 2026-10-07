import { GeneralDashboard } from '@/components/dashboards/GeneralDashboard';

export default function Page() {
    return (
        <div>
            <div className="mb-6">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="font-black text-xl text-foreground tracking-tight">
                            Security Operations Centre
                        </h1>
                        <p className="text-xs text-foreground-muted mt-0.5 uppercase tracking-wider font-medium">
                            Aggregated across all onboarded clients
                        </p>
                    </div>
                </div>
            </div>
            <GeneralDashboard />
        </div>
    );
}
