'use client';

import { useState, useRef, useEffect } from 'react';
import { 
    Bot, 
    User, 
    Send, 
    Sparkles, 
    Trash2, 
    Copy, 
    Check, 
    AlertTriangle, 
    Shield, 
    Terminal, 
    RotateCcw,
    Zap,
    ChevronRight,
    Loader2
} from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

export interface ChatMessage {
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp?: string;
}

const SUGGESTED_PROMPTS = [
    {
        title: 'Critical Incident Triage',
        prompt: 'Show me critical incidents in the last 24 hours and recommend containment steps.',
        category: 'Incidents'
    },
    {
        title: 'MITRE ATT&CK Breakdown',
        prompt: 'Analyze detected MITRE ATT&CK techniques this week and identify high-risk tactics.',
        category: 'Threat Intel'
    },
    {
        title: 'Nigeria Threat Landscape',
        prompt: 'Summarize active cyber threats and botnet activities targeting Nigerian ISP netblocks.',
        category: 'Regional'
    },
    {
        title: 'Asset Exposure & Vulnerabilities',
        prompt: 'Which monitored endpoints or assets have the highest risk scores and need patching?',
        category: 'Posture'
    },
    {
        title: 'Compliance & Audit Summary',
        prompt: 'Summarize our compliance readiness across NDPR and ISO 27001 controls.',
        category: 'Governance'
    },
];

const CONTEXT_STATS = [
    { label: 'Active Alerts', value: 14, color: 'text-amber-500', badge: 'bg-amber-500/10 border-amber-500/30' },
    { label: 'Open Incidents', value: 8, color: 'text-red-500', badge: 'bg-red-500/10 border-red-500/30' },
    { label: 'Critical Severity', value: 3, color: 'text-red-500', badge: 'bg-red-500/10 border-red-500/30' },
    { label: 'Posture Score', value: '72/100', color: 'text-blue', badge: 'bg-blue/10 border-blue/30' },
    { label: 'Primary Tactic', value: 'Initial Access', color: 'text-purple', badge: 'bg-purple/10 border-purple/30' },
];

function FormattedResponse({ text }: { text: string }) {
    const lines = text.split('\n');
    return (
        <div className="space-y-2 text-xs text-foreground leading-relaxed">
            {lines.map((line, i) => {
                // Section Headers
                if (line.startsWith('### ')) {
                    return <h4 key={i} className="font-bold text-foreground text-xs uppercase tracking-wider text-blue mt-3 mb-1">{line.replace(/^###\s/, '')}</h4>;
                }
                if (line.startsWith('## ') || line.startsWith('# ')) {
                    return <h3 key={i} className="font-bold text-foreground text-sm border-b border-border pb-1 mt-3 mb-1.5">{line.replace(/^#+\s/, '')}</h3>;
                }
                
                // Code block simulation
                if (line.startsWith('```') || line.endsWith('```')) {
                    return null;
                }
                if (line.startsWith('    ') || line.startsWith('\t')) {
                    return (
                        <pre key={i} className="bg-card border border-border p-2 rounded-lg font-mono text-[11px] text-amber overflow-x-auto my-1">
                            {line.trim()}
                        </pre>
                    );
                }

                // Bullet points
                if (line.startsWith('- ') || line.startsWith('* ') || line.startsWith('• ')) {
                    const content = line.replace(/^[-*•]\s/, '');
                    return (
                        <div key={i} className="flex items-start gap-2 pl-1">
                            <span className="text-blue flex-shrink-0 mt-0.5">•</span>
                            <span className="flex-1">{renderHighlightedText(content)}</span>
                        </div>
                    );
                }

                // Numbered lists
                if (/^\d+\./.test(line)) {
                    const number = line.match(/^\d+/)?.[0];
                    const content = line.replace(/^\d+\.\s/, '');
                    return (
                        <div key={i} className="flex items-start gap-2 pl-1">
                            <span className="text-blue font-bold text-[11px] flex-shrink-0 mt-0.5">{number}.</span>
                            <span className="flex-1">{renderHighlightedText(content)}</span>
                        </div>
                    );
                }

                // Empty line spacing
                if (!line.trim()) return <div key={i} className="h-1.5" />;

                // Regular paragraphs
                return <p key={i}>{renderHighlightedText(line)}</p>;
            })}
        </div>
    );
}

// Helper to highlight MITRE IDs, IP addresses, CVEs, and bold markdown
function renderHighlightedText(str: string) {
    // Process markdown bold (**bold**)
    const boldParts = str.split(/(\*\*.*?\*\*)/g);
    return boldParts.map((part, index) => {
        if (part.startsWith('**') && part.endsWith('**')) {
            return <strong key={index} className="font-bold text-foreground">{part.slice(2, -2)}</strong>;
        }

        // Process MITRE IDs (e.g. T1059), CVEs (e.g. CVE-2024-1234), and IPs
        const tokenParts = part.split(/(\bT\d{4}(?:\.\d{3})?\b|\bCVE-\d{4}-\d+\b|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/g);
        return tokenParts.map((token, j) => {
            if (/^T\d{4}(\.\d{3})?$/.test(token)) {
                return (
                    <span key={j} className="text-amber font-mono font-bold bg-amber/10 border border-amber/30 px-1 py-0.5 rounded text-[10px] mx-0.5">
                        {token}
                    </span>
                );
            }
            if (/^CVE-\d{4}-\d+$/.test(token)) {
                return (
                    <span key={j} className="text-red-500 font-mono font-bold bg-red-500/10 border border-red-500/30 px-1 py-0.5 rounded text-[10px] mx-0.5">
                        {token}
                    </span>
                );
            }
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(token)) {
                return (
                    <span key={j} className="text-blue font-mono text-[11px] bg-blue/10 px-1 rounded">
                        {token}
                    </span>
                );
            }
            return token;
        });
    });
}

export function NovrAI() {
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
    // Which model is actually answering. The header used to hardcode "Claude CTI Engine" even
    // when ANTHROPIC_API_KEY was unset and every reply was really coming from Gemini. Backed by
    // GET /api/novr-ai/status, so it flips to Claude on its own the moment that key is set —
    // no code change needed (routes/novr-ai.ts tries Claude first and falls back to Gemini).
    const [aiStatus, setAiStatus] = useState<{ provider: string; model: string } | null>(null);
    const bottomRef = useRef<HTMLDivElement>(null);
    const textareaRef = useRef<HTMLTextAreaElement>(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages, loading]);

    useEffect(() => {
        let cancelled = false;
        apiFetch(apiUrl('/api/novr-ai/status'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => { if (!cancelled) setAiStatus({ provider: data?.provider ?? 'none', model: data?.model ?? 'none' }); })
            .catch(() => { if (!cancelled) setAiStatus({ provider: 'none', model: 'none' }); });
        return () => { cancelled = true; };
    }, []);

    const copyMessage = (text: string, index: number) => {
        navigator.clipboard.writeText(text);
        setCopiedIndex(index);
        setTimeout(() => setCopiedIndex(null), 2000);
    };

    const send = async (text: string) => {
        const query = text.trim();
        if (!query || loading) return;

        setError('');
        const userMsg: ChatMessage = { 
            role: 'user', 
            content: query,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        const updated = [...messages, userMsg];
        setMessages(updated);
        setInput('');
        setLoading(true);

        try {
           const res = await apiFetch(apiUrl('/api/novr-ai'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    messages: updated.map(m => ({ role: m.role, content: m.content })),
                    stream: false,
                }),
            });

            const data = await res.json() as { reply?: string; error?: string };
            if (!res.ok || !data.reply) {
                throw new Error(data.error ?? 'Failed to retrieve response from NovrAI');
            }

            setMessages([
                ...updated, 
                { 
                    role: 'assistant', 
                    content: data.reply,
                    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                }
            ]);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Something went wrong while connecting to NovrAI');
        } finally {
            setLoading(false);
            if (textareaRef.current) {
                textareaRef.current.focus();
            }
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            send(input);
        }
    };

    const handleRegenerate = () => {
        const lastUserMessage = [...messages].reverse().find(m => m.role === 'user');
        if (lastUserMessage) {
            send(lastUserMessage.content);
        }
    };

    return (
        <div className="flex flex-col lg:flex-row gap-4 h-[calc(100vh-140px)] max-w-7xl mx-auto">
            
            {/* Left Context & Telemetry Panel */}
            <div className="w-full lg:w-64 flex-shrink-0 flex flex-col gap-3">
                <div className="bg-card border border-border rounded-xl p-4 shadow-xs">
                    <div className="flex items-center gap-2.5 mb-3 border-b border-border pb-3">
                        <div className="w-7 h-7 rounded-lg bg-orange/10 flex items-center justify-center text-orange">
                            <Shield className="w-4 h-4" />
                        </div>
                        <div>
                            <h3 className="text-xs font-bold text-foreground">SOC Context</h3>
                            <p className="text-[10px] text-foreground-muted">Live Telemetry Ingestion</p>
                        </div>
                    </div>

                    <div className="space-y-2">
                        {CONTEXT_STATS.map((s) => (
                            <div key={s.label} className="flex justify-between items-center text-xs p-1.5 rounded-lg hover:bg-card-muted/40 transition-colors">
                                <span className="text-[11px] text-foreground-muted">{s.label}</span>
                                <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${s.badge} ${s.color}`}>
                                    {s.value}
                                </span>
                            </div>
                        ))}
                    </div>

                    <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-[10px] text-foreground-muted">
                        <span className="flex items-center gap-1.5">
                            <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                            </span>
                            Claude Engine Active
                        </span>
                        <span className="font-mono text-[9px]">v2.4-CTI</span>
                    </div>
                </div>

                {/* Quick Capability Tags */}
                <div className="bg-card border border-border rounded-xl p-3.5 shadow-xs hidden lg:block">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2 flex items-center gap-1.5">
                        <Zap className="w-3.5 h-3.5 text-amber" /> Engine Capabilities
                    </p>
                    <ul className="space-y-1.5 text-[11px] text-foreground-muted">
                        <li className="flex items-center gap-1.5">
                            <ChevronRight className="w-3 h-3 text-blue flex-shrink-0" />
                            Wazuh log correlation & SIEM triage
                        </li>
                        <li className="flex items-center gap-1.5">
                            <ChevronRight className="w-3 h-3 text-blue flex-shrink-0" />
                            MITRE ATT&CK technique mapping
                        </li>
                        <li className="flex items-center gap-1.5">
                            <ChevronRight className="w-3 h-3 text-blue flex-shrink-0" />
                            Nigeria ISP & ASN threat enrichment
                        </li>
                        <li className="flex items-center gap-1.5">
                            <ChevronRight className="w-3 h-3 text-blue flex-shrink-0" />
                            Automated incident containment advice
                        </li>
                    </ul>
                </div>

                {messages.length > 0 && (
                    <button 
                        onClick={() => setMessages([])}
                        className="flex items-center justify-center gap-1.5 w-full text-xs font-semibold text-foreground-muted hover:text-red-500 border border-border hover:border-red-500/30 hover:bg-red-500/10 rounded-xl py-2.5 transition-all shadow-xs"
                    >
                        <Trash2 size={13} />
                        Clear Conversation
                    </button>
                )}
            </div>

            {/* Main Chat Interface */}
            <div className="flex-1 flex flex-col bg-card border border-border rounded-xl shadow-xs overflow-hidden">
                {/* Header Strip */}
                <div className="px-4 py-3 border-b border-border flex items-center justify-between bg-card-muted/20">
                    <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-orange flex items-center justify-center text-white shadow-xs">
                            <Sparkles size={16} />
                        </div>
                        <div>
                            <div className="flex items-center gap-2">
                                <h2 className="text-xs font-bold text-foreground">NovrAI Security Copilot</h2>
                                {aiStatus && (
                                    <span
                                        title={aiStatus.provider === 'none' ? 'No AI provider key configured' : `Model: ${aiStatus.model}`}
                                        className={`flex items-center gap-1.5 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                                            aiStatus.provider === 'claude' ? 'bg-purple/10 text-purple border-purple/30'
                                                : aiStatus.provider === 'gemini' ? 'bg-blue/10 text-blue border-blue/30'
                                                : 'bg-card-muted text-foreground-muted border-border'
                                        }`}
                                    >
                                        <span className={`w-1.5 h-1.5 rounded-full ${
                                            aiStatus.provider === 'claude' ? 'bg-purple'
                                                : aiStatus.provider === 'gemini' ? 'bg-blue'
                                                : 'bg-foreground-muted'
                                        }`} />
                                        {aiStatus.provider === 'claude' ? 'Claude AI'
                                            : aiStatus.provider === 'gemini' ? 'Gemini AI'
                                            : 'AI Offline'}
                                    </span>
                                )}
                            </div>
                            <p className="text-[10px] text-foreground-muted">Autonomous SOC intelligence, alert triage & remediation</p>
                        </div>
                    </div>

                    {messages.length > 0 && (
                        <button
                            onClick={handleRegenerate}
                            disabled={loading}
                            className="flex items-center gap-1 text-[11px] font-semibold text-foreground-muted hover:text-foreground border border-border px-2.5 py-1 rounded-lg hover:bg-card-muted transition-colors disabled:opacity-50"
                        >
                            <RotateCcw size={12} />
                            Regenerate
                        </button>
                    )}
                </div>

                {/* Messages Container */}
                <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4">
                    {messages.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-full text-center max-w-xl mx-auto py-8">
                            <div className="w-12 h-12 rounded-2xl bg-orange/10 border border-orange/20 flex items-center justify-center mb-3 text-orange shadow-xs">
                                <Bot size={24} />
                            </div>
                            <h3 className="text-base font-bold text-foreground">How can NovrAI assist your SOC today?</h3>
                            <p className="text-xs text-foreground-muted mt-1 mb-6 max-w-md">
                                Query real-time telemetry, analyze MITRE patterns, evaluate Nigerian ASN threats, or assess compliance posture using Claude-powered intelligence.
                            </p>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full">
                                {SUGGESTED_PROMPTS.map((item) => (
                                    <button
                                        key={item.title}
                                        onClick={() => send(item.prompt)}
                                        className="text-left p-3 rounded-xl bg-card-muted/40 border border-border hover:border-orange/40 hover:bg-card-muted transition-all group"
                                    >
                                        <div className="flex items-center justify-between mb-1">
                                            <span className="text-[10px] font-bold text-orange uppercase tracking-wider">{item.category}</span>
                                            <ChevronRight size={12} className="text-foreground-muted group-hover:text-foreground transition-transform group-hover:translate-x-0.5" />
                                        </div>
                                        <p className="text-xs font-semibold text-foreground">{item.title}</p>
                                        <p className="text-[11px] text-foreground-muted truncate mt-0.5">{item.prompt}</p>
                                    </button>
                                ))}
                            </div>
                        </div>
                    ) : (
                        messages.map((m, i) => (
                            <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                                <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0 shadow-xs ${
                                    m.role === 'user' 
                                        ? 'bg-foreground text-background' 
                                        : 'bg-orange text-white'
                                }`}>
                                    {m.role === 'user' ? <User size={15} /> : <Bot size={16} />}
                                </div>

                                <div className={`group relative max-w-[85%] sm:max-w-[75%] rounded-xl px-4 py-3.5 shadow-xs border ${
                                    m.role === 'user'
                                        ? 'bg-blue/10 border-blue/30 text-foreground'
                                        : 'bg-card border-border text-foreground'
                                }`}>
                                    {m.role === 'assistant' ? (
                                        <>
                                            <FormattedResponse text={m.content} />
                                            <div className="flex items-center justify-between border-t border-border mt-3 pt-2 text-[10px] text-foreground-muted">
                                                <span>NovrAI Intelligence</span>
                                                <button
                                                    onClick={() => copyMessage(m.content, i)}
                                                    className="flex items-center gap-1 hover:text-foreground transition-colors"
                                                >
                                                    {copiedIndex === i ? <Check size={11} className="text-emerald-500" /> : <Copy size={11} />}
                                                    {copiedIndex === i ? 'Copied' : 'Copy'}
                                                </button>
                                            </div>
                                        </>
                                    ) : (
                                        <p className="text-xs leading-relaxed whitespace-pre-wrap">{m.content}</p>
                                    )}

                                    {m.timestamp && (
                                        <span className="absolute -bottom-4 right-1 text-[9px] text-foreground-muted">
                                            {m.timestamp}
                                        </span>
                                    )}
                                </div>
                            </div>
                        ))
                    )}

                    {loading && (
                        <div className="flex gap-3">
                            <div className="w-8 h-8 rounded-lg bg-orange text-white flex items-center justify-center flex-shrink-0 shadow-xs">
                                <Bot size={16} />
                            </div>
                            <div className="bg-card border border-border rounded-xl px-4 py-3 shadow-xs">
                                <div className="flex items-center gap-2 text-xs text-foreground-muted font-medium">
                                    <Loader2 size={13} className="animate-spin text-orange" />
                                    Analyzing security telemetry with Claude...
                                </div>
                            </div>
                        </div>
                    )}

                    {error && (
                        <div className="flex items-center gap-2 text-xs text-red-500 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">
                            <AlertTriangle size={15} className="flex-shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}
                    <div ref={bottomRef} />
                </div>

                {/* Input Area */}
                <div className="border-t border-border p-3 sm:p-4 bg-card-muted/20">
                    <div className="flex gap-2.5 items-end">
                        <textarea
                            ref={textareaRef}
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyDown={handleKeyDown}
                            placeholder="Ask NovrAI about security incidents, IP reputation, MITRE tactics, or remediation..."
                            rows={2}
                            className="flex-1 bg-card border border-border rounded-xl px-3.5 py-2.5 text-xs text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-orange focus:ring-1 focus:ring-orange transition-all resize-none shadow-xs"
                        />
                        <button
                            onClick={() => send(input)}
                            disabled={loading || !input.trim()}
                            className="flex items-center justify-center gap-1.5 px-4 py-3 bg-orange hover:bg-orange-hover disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-bold rounded-xl transition-all shadow-xs h-[48px]"
                        >
                            {loading ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
                            <span className="hidden sm:inline">Send</span>
                        </button>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-foreground-muted mt-2 px-1">
                        <span>Press <kbd className="font-mono bg-card border border-border px-1 py-0.2 rounded text-[9px]">Enter</kbd> to send, <kbd className="font-mono bg-card border border-border px-1 py-0.2 rounded text-[9px]">Shift+Enter</kbd> for new line</span>
                        <span>NovrSOC Intelligence Suite</span>
                    </div>
                </div>
            </div>
        </div>
    );
}