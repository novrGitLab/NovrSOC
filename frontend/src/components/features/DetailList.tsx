export function DetailItem({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div className="flex gap-4 py-4 border-t border-gray-100 first:border-t-0">
            <svg className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M5 13L9 17L19 7" />
            </svg>
            <div>
                <h4 className="text-sm font-bold text-gray-900 mb-1">{title}</h4>
                <p className="text-sm text-gray-500 leading-relaxed">{children}</p>
            </div>
        </div>
    );
}

export function DetailList({ children }: { children: React.ReactNode }) {
    return <div className="mt-2">{children}</div>;
}
