'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  FileCheck,
  Clock,
  Fingerprint,
  Layers,
  ArrowLeft,
  ExternalLink,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';
import { StatusBadge } from '@/components/ui/StatusBadge';

function VerifyContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialCode = searchParams.get('code') || '';

  const [tokenInput, setTokenInput] = useState(initialCode);
  const [loading, setLoading] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState('');

  const performVerification = async (code: string) => {
    if (!code.trim()) return;
    try {
      setLoading(true);
      setErrorMsg('');
      setVerificationResult(null);

      const res = await fetch(`/api/v1/reports/verify/${encodeURIComponent(code.trim())}`);
      const data = await res.json();

      if (res.ok && data.verified) {
        setVerificationResult(data);
      } else {
        setErrorMsg(data.message || 'Verification token not found or expired.');
      }
    } catch (err) {
      setErrorMsg('Failed to communicate with the verification server.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialCode) {
      performVerification(initialCode);
    }
  }, [initialCode]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanToken = tokenInput.trim();
    if (cleanToken) {
      router.replace(`/verify?code=${encodeURIComponent(cleanToken)}`, { scroll: false });
      performVerification(cleanToken);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-12 px-4 sm:px-6 lg:px-8 space-y-8 animate-page-in">
      {/* HEADER */}
      <div className="flex items-center justify-between border-b border-white/10 pb-4">
        <div>
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-xs font-mono text-zinc-400 hover:text-amber-400 transition mb-2"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Terminal
          </Link>
          <h1 className="font-display text-3xl sm:text-4xl text-white uppercase tracking-wider flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-amber-500/10 border border-amber-500/30 p-1 flex items-center justify-center overflow-hidden shadow-[0_0_15px_rgba(245,158,11,0.2)]">
              <img src="/logo.svg" alt="Silhouette Reaper" className="w-full h-full object-contain rounded-lg transform scale-115 drop-shadow-[0_0_10px_rgba(245,158,11,0.5)]" />
            </div>
            Report Integrity Verification
          </h1>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Independent cryptographic ledger verification for Silhouette Reaper examination reports
          </p>
        </div>
      </div>

      {/* SEARCH CARD */}
      <GlassCard variant="default" className="space-y-4">
        <form onSubmit={handleSubmit} className="space-y-3">
          <label className="block text-xs font-mono uppercase tracking-wider text-zinc-300">
            Enter Verification Token (e.g. VRF-9X4A-8B2K-7P1M)
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              placeholder="VRF-XXXX-XXXX-XXXX"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              className="flex-1 bg-black/70 border border-white/10 focus:border-amber-500 rounded-xl px-4 py-3 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500 transition shadow-inner uppercase"
              required
            />
            <button
              type="submit"
              disabled={loading}
              className="px-8 py-3 bg-amber-500 hover:bg-amber-400 text-black font-heading font-bold uppercase tracking-wider text-xs rounded-xl shadow-[0_0_20px_rgba(245,158,11,0.3)] transition disabled:opacity-50 cursor-pointer"
            >
              {loading ? 'Verifying...' : 'Validate Seal'}
            </button>
          </div>
        </form>
      </GlassCard>

      {/* ERROR DISPLAY */}
      {errorMsg && (
        <GlassCard variant="subtle" className="border-rose-500/40 bg-rose-500/5 space-y-3">
          <div className="flex items-center gap-2 text-rose-400 font-heading text-sm uppercase font-bold">
            <ShieldAlert className="w-5 h-5" />
            Verification Failed
          </div>
          <p className="text-xs text-zinc-300 font-sans">{errorMsg}</p>
        </GlassCard>
      )}

      {/* VERIFIED SUCCESS CARD */}
      {verificationResult && (
        <div className="space-y-6 animate-fadeIn">
          <div className="glass-panel-amber p-6 rounded-2xl border-emerald-500/60 shadow-[0_0_30px_rgba(16,185,129,0.15)] space-y-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
              <div className="flex items-center gap-3.5">
                <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/40 p-1.5 flex items-center justify-center text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.25)] overflow-hidden">
                  <img src="/logo.svg" alt="Silhouette Reaper Seal" className="w-full h-full object-contain rounded-xl transform scale-115" />
                </div>
                <div>
                  <div className="font-heading text-lg font-bold text-white uppercase tracking-wide flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    AUTHENTIC & CRYPTOGRAPHICALLY VERIFIED
                  </div>
                  <div className="font-mono text-xs text-emerald-400">
                    {verificationResult.verification_message}
                  </div>
                </div>
              </div>
              <StatusBadge status="AUTHENTIC_AND_VERIFIED" size="md" />
            </div>

            {/* 7-DAY RETENTION & CUSTODY BANNER */}
            <div className="p-3.5 rounded-xl bg-amber-500/[0.08] border border-amber-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
              <div className="flex items-center gap-2 text-amber-300">
                <Clock className="w-4 h-4 text-amber-400 flex-shrink-0" />
                <span>
                  <strong>7-Day Proof Ledger:</strong> Valid until{' '}
                  {verificationResult.expires_at
                    ? new Date(verificationResult.expires_at).toUTCString()
                    : '7 days from issuance'}{' '}
                  <span className="text-emerald-400 font-bold">
                    ({verificationResult.retention_days_remaining ?? 7} days remaining)
                  </span>
                </span>
              </div>
              {verificationResult.session_purged && (
                <div className="text-[11px] px-2.5 py-1 bg-zinc-800/80 text-zinc-300 rounded-lg border border-white/10 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
                  <span>Raw Vault Zero-Filled & Purged</span>
                </div>
              )}
            </div>

            {/* METADATA GRID */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div className="bg-black/50 p-4 rounded-xl border border-white/5 space-y-1.5">
                <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Investigation ID</span>
                <span className="text-amber-400 font-bold text-sm">{verificationResult.investigation_id}</span>
              </div>

              <div className="bg-black/50 p-4 rounded-xl border border-white/5 space-y-1.5">
                <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Report Generation Timestamp (UTC)</span>
                <span className="text-zinc-200">{new Date(verificationResult.generated_at).toUTCString()}</span>
              </div>

              <div className="bg-black/50 p-4 rounded-xl border border-white/5 space-y-1.5 sm:col-span-2">
                <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Document SHA-256 Digest</span>
                <span className="text-emerald-400 font-bold break-all text-[11px]">{verificationResult.report_sha256}</span>
              </div>

              <div className="bg-black/50 p-4 rounded-xl border border-white/5 space-y-1.5 sm:col-span-2">
                <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Cryptographic Merkle Root</span>
                <span className="text-amber-400 font-bold break-all text-[11px]">{verificationResult.merkle_root}</span>
              </div>
            </div>

            {/* INVESTIGATION MANIFEST */}
            {verificationResult.manifest && (
              <div className="bg-black/40 p-4 rounded-xl border border-white/5 space-y-3">
                <div className="text-xs font-heading font-bold text-zinc-300 uppercase tracking-wider">
                  Verified Investigation Manifest
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-xs font-mono">
                  <div className="bg-white/5 p-2 rounded-lg">
                    <div className="text-[10px] text-zinc-400">Evidence Count</div>
                    <div className="text-white font-bold text-base">{verificationResult.manifest.evidence_count}</div>
                  </div>
                  <div className="bg-white/5 p-2 rounded-lg">
                    <div className="text-[10px] text-zinc-400">Extracted Artifacts</div>
                    <div className="text-white font-bold text-base">{verificationResult.manifest.artifact_count}</div>
                  </div>
                  <div className="bg-white/5 p-2 rounded-lg">
                    <div className="text-[10px] text-zinc-400">Findings Generated</div>
                    <div className="text-white font-bold text-base">{verificationResult.manifest.finding_count}</div>
                  </div>
                  <div className="bg-white/5 p-2 rounded-lg">
                    <div className="text-[10px] text-zinc-400">Timeline Events</div>
                    <div className="text-white font-bold text-base">{verificationResult.manifest.timeline_event_count}</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function VerifyPage() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col items-center justify-center min-h-[65vh] space-y-6 font-mono text-xs text-amber-400">
          <div className="relative">
            <div className="w-20 h-20 rounded-2xl bg-[#0a0d14] border border-amber-500/40 p-2.5 flex items-center justify-center shadow-[0_0_30px_rgba(245,158,11,0.3)] animate-pulse overflow-hidden">
              <img src="/logo.svg" alt="Silhouette Reaper" className="w-full h-full object-contain rounded-xl transform scale-115" />
            </div>
            <div className="absolute -inset-2 border-2 border-amber-500/30 border-t-amber-400 rounded-3xl animate-spin" />
          </div>
          <div className="font-heading font-bold text-sm uppercase tracking-wider text-white">
            Loading Verification Portal...
          </div>
        </div>
      }
    >
      <VerifyContent />
    </Suspense>
  );
}
