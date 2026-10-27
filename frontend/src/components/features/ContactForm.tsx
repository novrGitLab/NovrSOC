'use client';

import { useState } from 'react';

// Mirrors the static site's behaviour: opens the visitor's email client with a prefilled
// message instead of submitting anywhere. No data is stored by this site.

export function ContactForm() {
    const [note, setNote] = useState('');

    function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        const form = e.currentTarget;
        if (!form.reportValidity()) return;
        const data = new FormData(form);
        const val = (k: string) => String(data.get(k) ?? '').trim();
        const subject = 'Cybernovr enquiry — ' + val('interest');
        const body = `Full name: ${val('name')}\nWork email: ${val('email')}\nOrganisation: ${val('company')}\nInterest: ${val('interest')}\n\nMessage:\n${val('message')}`;
        setNote('Your email application will open with the message prepared. Please send it from there.');
        window.location.href = 'mailto:soc@cybernovr.com?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
    }

    return (
        <form onSubmit={handleSubmit} className="bg-white border border-gray-100 rounded-2xl p-8 shadow-sm">
            <h3 className="text-xl font-black text-gray-900 mb-1">Request a conversation</h3>
            <p className="text-xs text-gray-400 mb-6">
                This form opens your email app with a prefilled message; it does not store your data on this website.
            </p>
            <div className="space-y-4">
                <div>
                    <label htmlFor="name" className="block text-xs font-bold text-gray-700 mb-1.5">Full name *</label>
                    <input id="name" name="name" required placeholder="Your full name"
                        className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500" />
                </div>
                <div>
                    <label htmlFor="email" className="block text-xs font-bold text-gray-700 mb-1.5">Work email *</label>
                    <input id="email" name="email" type="email" required placeholder="name@company.com"
                        className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500" />
                </div>
                <div>
                    <label htmlFor="company" className="block text-xs font-bold text-gray-700 mb-1.5">Organisation *</label>
                    <input id="company" name="company" required placeholder="Your organisation"
                        className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500" />
                </div>
                <div>
                    <label htmlFor="interest" className="block text-xs font-bold text-gray-700 mb-1.5">Interested in</label>
                    <select id="interest" name="interest"
                        className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                        <option>NovrSOC Platform</option>
                        <option>CNII Watch</option>
                        <option>Vulnerability Management</option>
                        <option>Threat Intelligence</option>
                        <option>Detection &amp; Response</option>
                        <option>Partnership / Other</option>
                    </select>
                </div>
                <div>
                    <label htmlFor="message" className="block text-xs font-bold text-gray-700 mb-1.5">What would you like to discuss?</label>
                    <textarea id="message" name="message" rows={5} placeholder="Tell us about your priorities..."
                        className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500" />
                </div>
                <button type="submit"
                    className="w-full bg-purple text-white font-black py-3.5 rounded-xl hover:bg-purple-hover transition-colors">
                    Prepare email ↗
                </button>
                {note && <p className="text-xs text-purple font-medium" aria-live="polite">{note}</p>}
            </div>
        </form>
    );
}
