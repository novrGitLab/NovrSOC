'use client';

import { useState } from 'react';
import { usePathname } from 'next/navigation';
import { X, ChevronRight } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

const QUICK_QUESTIONS = [
    'What does this page do?',
    'How do I add a new endpoint?',
    'How do I configure DMARC monitoring?',
    'What does the Risk Score mean?',
    'How do I respond to an incident?',
];

interface Message { role: 'user' | 'assistant'; content: string }

export function HelpAssistant() {
    const pathname = usePathname();
    const [open, setOpen] = useState(false);
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);

    const ask = async (text: string) => {
        if (!text.trim() || loading) return;
        const updated: Message[] = [...messages, { role: 'user', content: text }];
        setMessages(updated);
        setInput('');
        setLoading(true);
        try {
            const res = await apiFetch(apiUrl('/api/novr-ai'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ messages: updated, page: pathname }),
            });
            const data = (await res.json()) as { reply?: string; error?: string };
            setMessages([...updated, { role: 'assistant', content: data.reply ?? data.error ?? 'Something went wrong.' }]);
        } catch {
            setMessages([...updated, { role: 'assistant', content: 'Something went wrong reaching NovrAI.' }]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed bottom-6 right-6 z-50 print:hidden">
            {open && (
                <div className="mb-3 w-[320px] bg-white border border-grey-100 rounded-2xl shadow-xl overflow-hidden flex flex-col max-h-[70vh]">
                    <div className="bg-blue px-4 py-3 flex items-center justify-between flex-shrink-0">
                        <div className="flex items-center gap-2.5">
                            {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
                            <img src="/novrsoc.jpg" alt="NovrAI" className="w-6 h-6 rounded object-contain shrink-0" />
                            <div>
                                <div className="text-white font-semibold text-sm">NovrAI Assistant</div>
                                <div className="text-white/60 text-xs">Ask me anything about this page</div>
                            </div>
                        </div>
                        <button onClick={() => setOpen(false)} className="text-white/60 hover:text-white" aria-label="Close">
                            <X size={16} />
                        </button>
                    </div>

                    {messages.length === 0 ? (
                        <div className="p-4">
                            <p className="text-xs text-grey-500 mb-3 font-medium uppercase tracking-wide">Quick Help</p>
                            <div className="space-y-2">
                                {QUICK_QUESTIONS.map((q) => (
                                    <button
                                        key={q}
                                        onClick={() => ask(q)}
                                        className="w-full text-left text-xs text-grey-800 hover:text-blue flex items-center justify-between py-2 px-3 rounded-lg hover:bg-blue/5 transition-colors border border-grey-100"
                                    >
                                        {q}
                                        <ChevronRight size={12} className="text-grey-500 flex-shrink-0" />
                                    </button>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <div className="p-4 space-y-3 overflow-y-auto flex-1">
                            {messages.map((m, i) => (
                                <div key={i} className={`text-xs leading-relaxed rounded-lg px-3 py-2 ${
                                    m.role === 'user' ? 'bg-blue/10 text-grey-800 ml-6' : 'bg-grey-50 text-grey-800 mr-2 whitespace-pre-wrap'
                                }`}>
                                    {m.content}
                                </div>
                            ))}
                            {loading && <div className="text-xs text-grey-500 px-3">Thinking…</div>}
                        </div>
                    )}

                    <div className="px-4 pb-4 pt-2 flex-shrink-0">
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={(e) => { if (e.key === 'Enter') ask(input); }}
                                placeholder="Ask a question..."
                                className="flex-1 text-xs border border-grey-100 rounded-lg px-3 py-2 focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 text-grey-800 placeholder:text-grey-500"
                            />
                            <button
                                onClick={() => ask(input)}
                                disabled={loading || !input.trim()}
                                className="bg-orange text-white rounded-lg px-3 py-2 text-xs font-medium hover:bg-orange-hover disabled:opacity-50 transition-colors"
                            >
                                Ask
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <button
                onClick={() => setOpen(!open)}
                className="w-12 h-12 bg-blue text-white rounded-full shadow-lg flex items-center justify-center hover:opacity-90 transition-opacity overflow-hidden"
                aria-label="Help assistant"
            >
                {open ? <X size={20} /> : <img src="/novrsoc.jpg" alt="NovrAI" className="w-6 h-6 rounded object-contain" />}
            </button>
        </div>
    );
}
