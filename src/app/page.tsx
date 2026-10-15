'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Shield,
  FileSearch,
  Lock,
  Cpu,
  Fingerprint,
  FileCheck2,
  Terminal,
  Clock,
  Layers,
  Sparkles,
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  FileCode2,
  Binary,
  Database,
  Search,
} from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { StatPill } from '@/components/ui/StatPill';

export default function LandingPage() {
  const router = useRouter();
  const [isStarting, setIsStarting] = useState(false);
  const [verifyToken, setVerifyToken] = useState('');

  const handleStartInvestigation = async () => {
    try {
      setIsStarting(true);
      const res = await fetch('/api/v1/investigations', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        sessionStorage.setItem(`session_secret_${data.investigation_id}`, data.session_secret);
        router.push(`/workspace/${data.investigation_id}?secret=${data.session_secret}`);
      }
    } catch (err) {
      console.error('Failed to start investigation:', err);
    } finally {
      setIsStarting(false);
    }
  };

  const handleVerifySubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (verifyToken.trim()) {
      router.push(`/verify?code=${encodeURIComponent(verifyToken.trim())}`);
    }
  };

  return (
    <div className="space-y-24 py-8 sm:py-16 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* CLEAN MINIMALIST HERO SECTION */}
      <section className="relative text-center space-y-8 pt-6 pb-8 max-w-4xl mx-auto">
        {/* BRAND CREST */}
        <div className="flex justify-center">
          <div className="relative flex items-center justify-center p-2 rounded-2xl bg-[#0e111a]/80 border border-white/10 shadow-2xl backdrop-blur-xl">
            <div className="w-16 h-16 sm:w-20 sm:h-20 rounded-xl bg-amber-500/10 border border-amber-500/20 p-2 flex items-center justify-center overflow-hidden">
              <img
                src="/logo.svg"
                alt="Silhouette Reaper"
                className="w-full h-full object-contain rounded-lg transform scale-110 drop-shadow-[0_0_10px_rgba(245,158,11,0.4)]"
              />
            </div>
          </div>
        </div>

        {/* SUBTLE CAPABILITY BADGE */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/[0.03] text-zinc-300 text-xs font-mono backdrop-blur-md">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-amber-400 font-bold uppercase tracking-wider">SILHOUETTE REAPER</span>
          <span className="text-zinc-500">·</span>
          <span>Anonymous Forensic Engine</span>
        </div>

        {/* CLEAN TYPOGRAPHIC HEADLINE */}
        <div className="space-y-4">
          <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-white leading-tight font-sans">
            Autonomous Digital Forensics <br />
            <span className="bg-gradient-to-r from-amber-400 via-amber-200 to-amber-500 bg-clip-text text-transparent">
              & Evidence Investigation
            </span>
          </h1>
          <p className="text-sm sm:text-base text-zinc-400 max-w-2xl mx-auto leading-relaxed font-sans">
            Ingest digital evidence into an isolated bit-stream vault. Extract metadata artifacts, detect malicious payload spoofing, reconstruct normalized timelines, and compile verifiable Merkle-sealed examination reports.
          </p>
        </div>

        {/* SLEEK ACTION BAR */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <button
            onClick={handleStartInvestigation}
            disabled={isStarting}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-6 py-3 bg-amber-500 hover:bg-amber-400 text-black font-semibold text-xs sm:text-sm rounded-xl transition-all shadow-[0_0_20px_rgba(245,158,11,0.25)] hover:shadow-[0_0_25px_rgba(245,158,11,0.4)] disabled:opacity-50 cursor-pointer"
          >
            <Shield className="w-4 h-4" />
            <span>{isStarting ? 'Allocating Workspace...' : 'Launch Forensic Workspace'}</span>
            <ArrowRight className="w-4 h-4 opacity-80" />
          </button>

          <Link
            href="/verify"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-3 text-xs sm:text-sm font-mono text-zinc-300 hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 hover:border-white/20 rounded-xl transition-all"
          >
            <FileCheck2 className="w-4 h-4 text-emerald-400" />
            <span>Verify Report Token</span>
          </Link>
        </div>

        {/* FORENSIC GUARANTEE PILLS */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-4 text-left">
          <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-amber-400 font-mono font-medium">
              <Lock className="w-3.5 h-3.5" /> 0-PII Authentication
            </div>
            <div className="text-[11px] text-zinc-400">Anonymous cryptographic session keys</div>
          </div>
          <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-mono font-medium">
              <Fingerprint className="w-3.5 h-3.5" /> Bit-Stream 0400
            </div>
            <div className="text-[11px] text-zinc-400">Immutable read-only evidence vault</div>
          </div>
          <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-cyan-400 font-mono font-medium">
              <Cpu className="w-3.5 h-3.5" /> Memory Sandbox
            </div>
            <div className="text-[11px] text-zinc-400">Isolated multi-engine stream parsers</div>
          </div>
          <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
            <div className="flex items-center gap-1.5 text-xs text-amber-300 font-mono font-medium">
              <ShieldCheck className="w-3.5 h-3.5" /> Merkle Verification
            </div>
            <div className="text-[11px] text-zinc-400">Cryptographically verifiable PDF reports</div>
          </div>
        </div>
      </section>

      {/* CORE CAPABILITIES GRID */}
      <section className="space-y-8">
        <div className="text-center space-y-2">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Genuine Technical <span className="bg-gradient-to-r from-amber-400 to-amber-200 bg-clip-text text-transparent">Examination Engines</span>
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400 font-sans max-w-xl mx-auto">
            Zero simulated telemetry. Every finding is linked directly to extracted byte-level artifacts.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <GlassCard variant="default" interactive className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Binary className="w-5 h-5" />
            </div>
            <h3 className="font-heading text-base font-bold text-white uppercase tracking-wide">
              File Identification & Extension Spoofing
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed font-sans">
              Sniffs true magic byte signatures (PE, ELF, PDF, ZIP, EVTX, JPEG, PNG, SQLite) and detects malicious extension mismatches (e.g. `.pdf` containing an executable header).
            </p>
            <div className="pt-2 flex flex-wrap gap-1.5">
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-amber-300">Magic Bytes</span>
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-amber-300">Shannon Entropy</span>
            </div>
          </GlassCard>

          <GlassCard variant="default" interactive className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Fingerprint className="w-5 h-5" />
            </div>
            <h3 className="font-heading text-base font-bold text-white uppercase tracking-wide">
              Multi-Algorithm Integrity Hashing
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed font-sans">
              Streams authoritative SHA-256 digests along with SHA-1 and MD5 compatibility hashes. Computes chunked block hashes for bit-level integrity verification.
            </p>
            <div className="pt-2 flex flex-wrap gap-1.5">
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-emerald-300">FIPS 180-4 SHA-256</span>
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-emerald-300">Block Digests</span>
            </div>
          </GlassCard>

          <GlassCard variant="default" interactive className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <FileSearch className="w-5 h-5" />
            </div>
            <h3 className="font-heading text-base font-bold text-white uppercase tracking-wide">
              Document & Deep Metadata Extraction
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed font-sans">
              Extracts EXIF camera and GPS telemetry from images, document catalogs and JavaScript streams from PDFs, and core revision properties and macros from Office OpenXML files.
            </p>
            <div className="pt-2 flex flex-wrap gap-1.5">
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-cyan-300">EXIF / GPS</span>
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-cyan-300">PDF / Office XML</span>
            </div>
          </GlassCard>

          <GlassCard variant="default" interactive className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="font-heading text-base font-bold text-white uppercase tracking-wide">
              Safe Container & Zip Slip Analysis
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed font-sans">
              Inspects ZIP and compressed archives for decompression bombs, path traversal vulnerabilities (`../`), nested archives, and individual entry timestamps.
            </p>
            <div className="pt-2 flex flex-wrap gap-1.5">
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-rose-300">Zip Slip Check</span>
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-rose-300">Bomb Threshold</span>
            </div>
          </GlassCard>

          <GlassCard variant="default" interactive className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Clock className="w-5 h-5" />
            </div>
            <h3 className="font-heading text-base font-bold text-white uppercase tracking-wide">
              Unified Chronological Timeline
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed font-sans">
              Consolidates all temporal artifacts into a unified UTC timeline with precision ratings (`DEFINITIVE`, `HEURISTIC`) and timestomp anomaly alerts.
            </p>
            <div className="pt-2 flex flex-wrap gap-1.5">
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-amber-300">ISO-8601 UTC</span>
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-amber-300">Timestomp Audit</span>
            </div>
          </GlassCard>

          <GlassCard variant="default" interactive className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <FileCode2 className="w-5 h-5" />
            </div>
            <h3 className="font-heading text-base font-bold text-white uppercase tracking-wide">
              Verifiable Forensic Reports
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed font-sans">
              Compiles publication-grade PDF examination reports with Merkle root seals, SHA-256 digests, and independent public verification tokens.
            </p>
            <div className="pt-2 flex flex-wrap gap-1.5">
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-emerald-300">Merkle Sealer</span>
              <span className="text-[10px] font-mono bg-zinc-800/80 px-2 py-0.5 rounded text-emerald-300">Public Verifier</span>
            </div>
          </GlassCard>
        </div>
      </section>

      {/* PIPELINE LIFECYCLE FLOW */}
      <section className="glass-panel p-8 rounded-2xl border-amber-500/30 space-y-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
          <div>
            <h2 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight">
              Investigation <span className="bg-gradient-to-r from-amber-400 to-amber-200 bg-clip-text text-transparent">Execution Pipeline</span>
            </h2>
            <p className="text-xs text-zinc-400 font-mono">Defense-in-depth state transitions for every registered evidence stream</p>
          </div>
          <StatusBadge status="PRESERVED_RO" size="md" />
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 text-center">
          <div className="bg-black/40 border border-white/10 p-3.5 rounded-xl space-y-1.5">
            <div className="text-[10px] font-mono text-amber-400 font-bold">STAGE 01</div>
            <div className="text-xs font-heading font-bold text-white uppercase">Intake & Vault</div>
            <div className="text-[10px] font-mono text-zinc-400">Bit-stream 0400</div>
          </div>
          <div className="bg-black/40 border border-white/10 p-3.5 rounded-xl space-y-1.5">
            <div className="text-[10px] font-mono text-amber-400 font-bold">STAGE 02</div>
            <div className="text-xs font-heading font-bold text-white uppercase">Multi-Hashing</div>
            <div className="text-[10px] font-mono text-zinc-400">SHA-256 / SHA-1</div>
          </div>
          <div className="bg-black/40 border border-white/10 p-3.5 rounded-xl space-y-1.5">
            <div className="text-[10px] font-mono text-amber-400 font-bold">STAGE 03</div>
            <div className="text-xs font-heading font-bold text-white uppercase">Magic Byte ID</div>
            <div className="text-[10px] font-mono text-zinc-400">Signature Match</div>
          </div>
          <div className="bg-black/40 border border-white/10 p-3.5 rounded-xl space-y-1.5">
            <div className="text-[10px] font-mono text-amber-400 font-bold">STAGE 04</div>
            <div className="text-xs font-heading font-bold text-white uppercase">Parser Engines</div>
            <div className="text-[10px] font-mono text-zinc-400">EXIF/PDF/Office/Log</div>
          </div>
          <div className="bg-black/40 border border-white/10 p-3.5 rounded-xl space-y-1.5">
            <div className="text-[10px] font-mono text-amber-400 font-bold">STAGE 05</div>
            <div className="text-xs font-heading font-bold text-white uppercase">Timeline & Rules</div>
            <div className="text-[10px] font-mono text-zinc-400">Artifact Linking</div>
          </div>
          <div className="bg-black/40 border border-white/10 p-3.5 rounded-xl space-y-1.5">
            <div className="text-[10px] font-mono text-amber-400 font-bold">STAGE 06</div>
            <div className="text-xs font-heading font-bold text-white uppercase">Merkle Report</div>
            <div className="text-[10px] font-mono text-zinc-400">Sealed PDF</div>
          </div>
        </div>
      </section>

      {/* VERIFY REPORT QUICK SEARCH */}
      <section className="glass-panel p-8 rounded-2xl border-white/10 space-y-6 max-w-3xl mx-auto text-center">
        <div className="flex justify-center">
          <div className="w-14 h-14 rounded-2xl bg-amber-500/10 border border-amber-500/30 p-1.5 flex items-center justify-center overflow-hidden shadow-[0_0_20px_rgba(245,158,11,0.25)]">
            <img src="/logo.svg" alt="Silhouette Reaper Seal" className="w-full h-full object-contain rounded-xl transform scale-115" />
          </div>
        </div>
        <div className="space-y-2">
          <div className="inline-flex items-center gap-1.5 text-xs font-mono text-emerald-400 uppercase tracking-wider">
            <ShieldCheck className="w-4 h-4" />
            Independent Third-Party Verification
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Verify Forensic Report Integrity
          </h2>
          <p className="text-xs text-zinc-400 font-sans max-w-lg mx-auto">
            Received a forensic examination report generated by Silhouette Reaper? Enter its verification token to validate its digital seal and Merkle root against our ledger.
          </p>
        </div>

        <form onSubmit={handleVerifySubmit} className="flex flex-col sm:flex-row gap-3 max-w-xl mx-auto">
          <input
            type="text"
            placeholder="e.g. VRF-9X4A-8B2K-7P1M"
            value={verifyToken}
            onChange={(e) => setVerifyToken(e.target.value)}
            className="flex-1 bg-black/70 border border-white/10 focus:border-amber-500 rounded-xl px-4 py-3 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500 transition shadow-inner"
          />
          <button
            type="submit"
            className="px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-black font-heading font-bold uppercase tracking-wider text-xs rounded-xl shadow-[0_0_20px_rgba(16,185,129,0.3)] transition"
          >
            Verify Seal
          </button>
        </form>
      </section>
    </div>
  );
}
