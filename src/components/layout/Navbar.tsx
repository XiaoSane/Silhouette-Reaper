'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Search, Terminal, PlusCircle, CheckCircle2, Lock } from 'lucide-react';

export const Navbar: React.FC = () => {
  const router = useRouter();
  const [showResumeModal, setShowResumeModal] = useState(false);
  const [resumeId, setResumeId] = useState('');
  const [resumeSecret, setResumeSecret] = useState('');
  const [resumeError, setResumeError] = useState('');
  const [isStarting, setIsStarting] = useState(false);

  const handleStartInvestigation = async () => {
    try {
      setIsStarting(true);
      const res = await fetch('/api/v1/investigations', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        // Store secret in session storage for convenience
        sessionStorage.setItem(`session_secret_${data.investigation_id}`, data.session_secret);
        router.push(`/workspace/${data.investigation_id}?secret=${data.session_secret}`);
      }
    } catch (err) {
      console.error('Failed to start investigation:', err);
    } finally {
      setIsStarting(false);
    }
  };

  const handleResume = (e: React.FormEvent) => {
    e.preventDefault();
    if (!resumeId.trim()) {
      setResumeError('Please enter an Investigation ID (e.g. INV-2026-XXXX)');
      return;
    }
    const cleanId = resumeId.trim();
    const cleanSecret = resumeSecret.trim();
    if (cleanSecret) {
      sessionStorage.setItem(`session_secret_${cleanId}`, cleanSecret);
    }
    setShowResumeModal(false);
    router.push(`/workspace/${cleanId}${cleanSecret ? `?secret=${cleanSecret}` : ''}`);
  };

  return (
    <>
      <header className="sticky top-0 z-50 border-b border-amber-500/20 bg-[#0a0a0f]/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded-lg bg-amber-500/10 border border-amber-500/40 p-1 flex items-center justify-center overflow-hidden group-hover:shadow-[0_0_15px_rgba(245,158,11,0.4)] transition">
              <img
                src="/logo.svg"
                alt="Silhouette Reaper Logo"
                className="w-full h-full object-contain rounded-md transform scale-115 drop-shadow-[0_0_8px_rgba(245,158,11,0.6)]"
              />
            </div>
            <div>
              <div className="font-heading font-bold tracking-wider text-base sm:text-lg text-white flex items-center gap-2">
                SILHOUETTE <span className="text-amber-400">REAPER</span>
              </div>
            </div>
          </Link>

          <nav className="flex items-center gap-2 sm:gap-4">
            <Link
              href="/verify"
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-zinc-300 hover:text-amber-400 hover:bg-white/5 rounded-lg border border-transparent hover:border-white/10 transition"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Verify Report</span>
            </Link>

            <button
              onClick={() => setShowResumeModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-zinc-300 hover:text-amber-400 hover:bg-white/5 rounded-lg border border-white/10 transition"
            >
              <Terminal className="w-3.5 h-3.5 text-amber-400" />
              <span className="hidden sm:inline">Resume Session</span>
            </button>

            <button
              onClick={handleStartInvestigation}
              disabled={isStarting}
              className="flex items-center gap-2 px-4 py-2 text-xs font-heading font-bold uppercase tracking-wider bg-amber-500 hover:bg-amber-400 text-black rounded-lg shadow-[0_0_20px_rgba(245,158,11,0.3)] transition transform hover:-translate-y-0.5 disabled:opacity-50"
            >
              <PlusCircle className="w-4 h-4" />
              <span>{isStarting ? 'Allocating...' : 'New Investigation'}</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Resume Modal */}
      {showResumeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="glass-panel w-full max-w-md p-6 rounded-2xl border-amber-500/30">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center gap-2.5 text-amber-400 font-heading text-sm uppercase font-bold tracking-wider">
                <div className="w-6 h-6 rounded-md bg-amber-500/10 border border-amber-500/30 p-0.5 flex items-center justify-center overflow-hidden">
                  <img src="/logo.svg" alt="Silhouette Reaper" className="w-full h-full object-contain rounded-sm" />
                </div>
                Resume Anonymous Session
              </div>
              <button
                onClick={() => setShowResumeModal(false)}
                className="text-zinc-500 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleResume} className="mt-4 space-y-4">
              <div>
                <label className="block text-[11px] font-mono uppercase text-zinc-400 mb-1">
                  Investigation ID
                </label>
                <input
                  type="text"
                  placeholder="e.g. INV-2026-A8F932D1"
                  value={resumeId}
                  onChange={(e) => {
                    setResumeId(e.target.value);
                    setResumeError('');
                  }}
                  className="w-full bg-black/60 border border-white/10 focus:border-amber-500 rounded-xl px-3.5 py-2.5 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500 transition"
                  required
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase text-zinc-400 mb-1">
                  Session Secret Token (Optional if saved)
                </label>
                <input
                  type="password"
                  placeholder="Paste 64-character hex secret"
                  value={resumeSecret}
                  onChange={(e) => setResumeSecret(e.target.value)}
                  className="w-full bg-black/60 border border-white/10 focus:border-amber-500 rounded-xl px-3.5 py-2.5 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500 transition"
                />
              </div>

              {resumeError && (
                <div className="text-[11px] font-mono text-rose-400 bg-rose-500/10 p-2.5 rounded-lg border border-rose-500/30">
                  {resumeError}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowResumeModal(false)}
                  className="px-4 py-2 text-xs font-mono text-zinc-400 hover:text-white rounded-lg hover:bg-white/5"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-heading font-bold uppercase tracking-wider bg-amber-500 hover:bg-amber-400 text-black rounded-lg transition"
                >
                  Connect Session
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
};
