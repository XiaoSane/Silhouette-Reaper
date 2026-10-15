import React from 'react';
import Link from 'next/link';
import { ShieldCheck, Lock, Database, FileText } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-white/5 bg-[#0a0a0f] py-8 text-xs text-zinc-400 font-mono mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 pb-8 border-b border-white/5">
          <div className="space-y-2">
            <div className="font-heading text-sm text-white font-bold tracking-wider flex items-center gap-2">
              <div className="w-6 h-6 rounded-md bg-amber-500/10 border border-amber-500/30 p-0.5 flex items-center justify-center overflow-hidden">
                <img src="/logo.svg" alt="Silhouette Reaper" className="w-full h-full object-contain rounded-sm" />
              </div>
              SILHOUETTE REAPER
            </div>
            <p className="text-[11px] text-zinc-400 leading-relaxed font-sans">
              Autonomous public digital forensics examination pipeline. Zero-execution isolated processing, verifiable Merkle reports, and deterministic artifact extraction.
            </p>
          </div>

          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              Security Architecture
            </div>
            <ul className="space-y-1 text-[11px] text-zinc-400">
              <li>• Bit-Stream Read-Only Vault (0400)</li>
              <li>• Pure In-Memory Parsers</li>
              <li>• Anti-Decompression Bomb Sandbox</li>
              <li>• Zero Shell Command Interpolation</li>
            </ul>
          </div>

          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5" />
              Privacy & Retention
            </div>
            <ul className="space-y-1 text-[11px] text-zinc-400">
              <li>• No Account / No PII Storage</li>
              <li>• 24-Hour Automated Zero-Fill Purge</li>
              <li>• Instant Session Destruction On-Demand</li>
              <li>• Anonymous Session Cryptography</li>
            </ul>
          </div>

          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5" />
              Verification & Tools
            </div>
            <ul className="space-y-1 text-[11px]">
              <li>
                <Link href="/verify" className="hover:text-amber-400 transition">
                  • Public Report Verification
                </Link>
              </li>
              <li>• Multi-Hash Registry (SHA-256/1/MD5)</li>
              <li>• Normalized UTC Chronology</li>
              <li>• Traceable Evidence Provenance</li>
            </ul>
          </div>
        </div>

        <div className="pt-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-[10px] text-zinc-400">
          <div>
            © {new Date().getFullYear()} SILHOUETTE REAPER FORENSICS LAB. ALL TECHNICAL OBSERVATIONS ARE DETERMINISTICALLY DERIVED.
          </div>
          <div className="flex items-center gap-4">
            <span className="text-emerald-400 flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              PIPELINE OPERATIONAL
            </span>
            <span>NODE V26 ENGINE</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
