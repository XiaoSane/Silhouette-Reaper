'use client';

import React, { useState, useEffect, useRef, Suspense } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import {
  Shield,
  Upload,
  Cpu,
  Layers,
  Clock,
  AlertTriangle,
  FileCheck2,
  FileText,
  Copy,
  Check,
  Trash2,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronRight,
  Database,
  Fingerprint,
  Info,
  Terminal,
  Activity,
  CheckCircle2,
  AlertCircle,
  FileSearch,
  Lock,
  Download,
  ShieldCheck,
  Eye,
} from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { StatPill } from '@/components/ui/StatPill';
import {
  InvestigationFullDetails,
  ForensicArtifact,
  TimelineEvent,
  ForensicFinding,
  EvidenceRecord,
  ProcessingStage,
} from '@/types/forensics';

function WorkspaceContent() {
  const params = useParams();
  const router = useRouter();
  const searchParams = useSearchParams();
  const investigationId = params.id as string;

  const [sessionSecret, setSessionSecret] = useState<string>('');
  const [details, setDetails] = useState<InvestigationFullDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<
    'overview' | 'evidence' | 'telemetry' | 'artifacts' | 'timeline' | 'findings' | 'report' | 'audit'
  >('overview');

  // Evidence Upload State
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadSuccess, setUploadSuccess] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Processing State
  const [processing, setProcessing] = useState(false);
  const [processMsg, setProcessMsg] = useState('');

  // Report State
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportError, setReportError] = useState('');

  // UI helpers
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedId, setCopiedId] = useState(false);
  const [copiedArtifactId, setCopiedArtifactId] = useState<string | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  // Search & Filter States
  const [artifactSearch, setArtifactSearch] = useState('');
  const [artifactCategory, setArtifactCategory] = useState('ALL');
  const [findingSeverity, setFindingSeverity] = useState('ALL');
  const [timelineConfidence, setTimelineConfidence] = useState('ALL');

  const [initStage, setInitStage] = useState(0);

  const hasInitializedRef = useRef(false);

  // Fetch Investigation Details (with minimum 5-second initialization guarantee)
  const fetchDetails = async (isInitial: boolean = false, overrideSecret?: string) => {
    try {
      if (isInitial) {
        setLoading(true);
        setInitStage(0);
      }
      const secret = overrideSecret !== undefined
        ? overrideSecret
        : (sessionSecret || (typeof window !== 'undefined' ? sessionStorage.getItem(`session_secret_${investigationId}`) : '') || '');
      const headers: Record<string, string> = {};
      if (secret) headers['x-session-secret'] = secret;

      if (isInitial) {
        // Enforce at least 5000ms duration with multi-phase animation stages
        const fetchPromise = fetch(`/api/v1/investigations/${investigationId}`, { headers });
        const delayPromise = new Promise((resolve) => {
          setTimeout(() => setInitStage(1), 1000);
          setTimeout(() => setInitStage(2), 2000);
          setTimeout(() => setInitStage(3), 3000);
          setTimeout(() => setInitStage(4), 4000);
          setTimeout(resolve, 5000);
        });

        const [res] = await Promise.all([fetchPromise, delayPromise]);
        const data = await res.json();
        if (res.ok && data.success) {
          setDetails(data.data);
        } else {
          console.error('Failed to fetch details:', data.error);
        }
      } else {
        const res = await fetch(`/api/v1/investigations/${investigationId}`, { headers });
        const data = await res.json();
        if (res.ok && data.success) {
          setDetails(data.data);
        }
      }
    } catch (err) {
      console.error('Network error fetching investigation:', err);
    } finally {
      if (isInitial) {
        setLoading(false);
      }
    }
  };

  // Single initial resolution of session secret and guaranteed single initialization fetch
  useEffect(() => {
    if (!investigationId || hasInitializedRef.current) return;
    hasInitializedRef.current = true;

    const urlSecret = searchParams.get('secret');
    const storedSecret = typeof window !== 'undefined' ? sessionStorage.getItem(`session_secret_${investigationId}`) : null;
    const resolvedSecret = urlSecret || storedSecret || '';
    if (resolvedSecret) {
      setSessionSecret(resolvedSecret);
      sessionStorage.setItem(`session_secret_${investigationId}`, resolvedSecret);
    }

    fetchDetails(true, resolvedSecret);
  }, [investigationId, searchParams]);

  // Handle File Upload
  const handleFileUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    const file = files[0];

    try {
      setUploading(true);
      setUploadError('');
      setUploadSuccess('');

      const formData = new FormData();
      formData.append('file', file);

      const secret = sessionSecret || sessionStorage.getItem(`session_secret_${investigationId}`) || '';
      const headers: Record<string, string> = {};
      if (secret) headers['x-session-secret'] = secret;

      const res = await fetch(`/api/v1/investigations/${investigationId}/evidence`, {
        method: 'POST',
        headers,
        body: formData,
      });
      const data = await res.json();

      if (res.ok && data.success) {
        setUploadSuccess(`Evidence "${file.name}" registered with SHA-256: ${data.data.primary_sha256.slice(0, 16)}...`);
        await fetchDetails();
      } else {
        setUploadError(data.error || 'Failed to upload evidence.');
      }
    } catch (err: any) {
      setUploadError(err.message || 'Error communicating with intake endpoint.');
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Trigger Forensic Examination (Only on Pending / Unexamined Evidence Items)
  const handleStartExamination = async () => {
    try {
      setProcessing(true);
      setProcessMsg('Executing modular forensic pipeline on pending evidence items...');

      const secret = sessionSecret || sessionStorage.getItem(`session_secret_${investigationId}`) || '';
      const headers: Record<string, string> = {};
      if (secret) headers['x-session-secret'] = secret;

      const res = await fetch(`/api/v1/investigations/${investigationId}/process`, {
        method: 'POST',
        headers,
      });
      const data = await res.json();

      if (res.ok && data.success) {
        const count = data.processed_count ?? 0;
        setProcessMsg(
          count > 0
            ? `Examination complete! Successfully processed ${count} pending evidence item(s).`
            : 'All registered evidence items have already been examined.'
        );
        await fetchDetails();
        setActiveTab('findings');
      } else {
        setProcessMsg(`Examination failed: ${data.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      setProcessMsg(`Execution error: ${err.message}`);
    } finally {
      setProcessing(false);
    }
  };

  // Generate Report
  const handleGenerateReport = async () => {
    try {
      setGeneratingReport(true);
      setReportError('');

      const secret = sessionSecret || sessionStorage.getItem(`session_secret_${investigationId}`) || '';
      const headers: Record<string, string> = {};
      if (secret) headers['x-session-secret'] = secret;

      const res = await fetch(`/api/v1/investigations/${investigationId}/reports`, {
        method: 'POST',
        headers,
      });
      const data = await res.json();

      if (res.ok && data.success) {
        await fetchDetails();
        setActiveTab('report');
      } else {
        setReportError(data.error || 'Failed to generate report.');
      }
    } catch (err: any) {
      setReportError(err.message || 'Error generating report.');
    } finally {
      setGeneratingReport(false);
    }
  };

  // Purge / Destroy Investigation
  const handleDeleteSession = async () => {
    try {
      const secret = sessionSecret || sessionStorage.getItem(`session_secret_${investigationId}`) || '';
      const headers: Record<string, string> = {};
      if (secret) headers['x-session-secret'] = secret;

      await fetch(`/api/v1/investigations/${investigationId}`, {
        method: 'DELETE',
        headers,
      });
      sessionStorage.removeItem(`session_secret_${investigationId}`);
      router.push('/');
    } catch (err) {
      console.error('Failed to delete session:', err);
    }
  };

  const copyToClipboard = async (text: string, type: 'id' | 'secret') => {
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      if (type === 'id') {
        setCopiedId(true);
        setTimeout(() => setCopiedId(false), 2000);
      } else {
        setCopiedSecret(true);
        setTimeout(() => setCopiedSecret(false), 2000);
      }
    } catch (err) {
      console.warn('Failed to copy to clipboard:', err);
    }
  };

  if (loading && !details) {
    const stageMessages = [
      'ALLOCATING ISOLATED FORENSIC SANDBOX...',
      'INITIALIZING DETERMINISTIC ANALYSIS ENGINES...',
      'MOUNTING READ-ONLY BIT-STREAM VAULT [0400]...',
      'SYNCHRONIZING CRYPTOGRAPHIC SESSION PROOFS...',
      'ESTABLISHING IMMUTABLE AUDIT CUSTODY LEDGER...',
    ];

    return (
      <div className="flex flex-col items-center justify-center min-h-[65vh] space-y-6 font-mono text-xs text-amber-400 animate-fadeIn">
        <div className="relative">
          <div className="w-20 h-20 rounded-2xl bg-[#0a0d14] border border-amber-500/40 p-2.5 flex items-center justify-center shadow-[0_0_30px_rgba(245,158,11,0.3)] animate-pulse overflow-hidden">
            <img src="/logo.svg" alt="Silhouette Reaper" className="w-full h-full object-contain rounded-xl transform scale-115" />
          </div>
          <div className="absolute -inset-2.5 border-2 border-amber-500/20 border-t-amber-400 rounded-3xl animate-spin" />
        </div>
        <div className="text-center space-y-2">
          <div className="font-heading font-bold text-base uppercase tracking-wider text-white">
            Connecting To Forensic Laboratory Vault
          </div>
          <div className="text-xs text-amber-400 font-mono tracking-wide h-5 flex items-center justify-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
            <span>{stageMessages[initStage] || stageMessages[0]}</span>
          </div>
          <div className="text-[11px] text-zinc-400 font-mono">
            INVESTIGATION ID: <span className="text-amber-400 font-bold">{investigationId}</span>
          </div>
        </div>

        {/* 5-Second Progressive Timer Bar */}
        <div className="w-56 h-1 bg-white/10 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-amber-500 to-amber-300 transition-all duration-1000 ease-out"
            style={{ width: `${Math.min(100, (initStage + 1) * 20)}%` }}
          />
        </div>
      </div>
    );
  }

  if (!details) {
    return (
      <div className="max-w-2xl mx-auto py-16 px-4 text-center space-y-6">
        <div className="glass-panel p-8 rounded-2xl border-rose-500/40 space-y-4">
          <div className="w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/30 p-2 flex items-center justify-center mx-auto overflow-hidden">
            <img src="/logo.svg" alt="Silhouette Reaper" className="w-full h-full object-contain rounded-xl opacity-50 grayscale" />
          </div>
          <h1 className="font-heading text-xl text-white font-bold uppercase">Investigation Session Not Found</h1>
          <p className="text-xs text-zinc-400 font-sans">
            Session <span className="text-amber-400 font-mono">{investigationId}</span> could not be located. It may have expired and been permanently wiped by the automated 24-hour retention daemon.
          </p>
          <Link
            href="/"
            className="inline-flex items-center gap-2 px-6 py-2.5 bg-amber-500 hover:bg-amber-400 text-black font-heading font-bold text-xs uppercase rounded-xl transition"
          >
            Start New Investigation
          </Link>
        </div>
      </div>
    );
  }

  // Filtered Artifacts
  const filteredArtifacts = details.artifacts.filter((art) => {
    const matchesCat = artifactCategory === 'ALL' || art.category === artifactCategory;
    const matchesSearch =
      artifactSearch === '' ||
      art.name.toLowerCase().includes(artifactSearch.toLowerCase()) ||
      art.artifact_type.toLowerCase().includes(artifactSearch.toLowerCase()) ||
      JSON.stringify(art.data_payload).toLowerCase().includes(artifactSearch.toLowerCase());
    return matchesCat && matchesSearch;
  });

  // Filtered Findings
  const filteredFindings = details.findings.filter((fnd) => {
    return findingSeverity === 'ALL' || fnd.severity === findingSeverity;
  });

  // Filtered Timeline
  const filteredTimeline = details.timeline.filter((tle) => {
    return timelineConfidence === 'ALL' || tle.confidence === timelineConfidence;
  });

  // Pending Evidence Count
  const pendingEvidenceCount = details.evidence.filter(
    (ev) => ev.processing_status === 'PENDING' || ev.processing_status === 'FAILED'
  ).length;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-page-in">
      {/* WORKSPACE HEADER BAR */}
      <div className="glass-panel p-6 rounded-2xl border-amber-500/30 space-y-4">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 border-b border-white/10 pb-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-amber-500/10 border border-amber-500/40 p-1 flex items-center justify-center overflow-hidden shadow-[0_0_15px_rgba(245,158,11,0.3)]">
              <img src="/logo.svg" alt="Silhouette Reaper" className="w-full h-full object-contain rounded-lg transform scale-115 drop-shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-heading text-lg sm:text-xl font-bold text-white tracking-wider">
                  INVESTIGATION: <span className="text-amber-400 font-mono">{details.session.investigation_id}</span>
                </span>
                <button
                  onClick={() => copyToClipboard(details.session.investigation_id, 'id')}
                  title="Copy Investigation ID"
                  className="text-zinc-400 hover:text-white transition p-1"
                >
                  {copiedId ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <div className="text-[10px] font-mono text-zinc-400 flex items-center gap-3 mt-0.5">
                <span>Created: {new Date(details.session.created_at).toUTCString()}</span>
                <span>•</span>
                <span>Retention: {details.session.retention_hours}h Auto-Purge</span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <StatusBadge status={details.session.status} size="md" />

            {sessionSecret && (
              <button
                onClick={() => copyToClipboard(sessionSecret, 'secret')}
                className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono bg-zinc-900 border border-white/10 hover:border-amber-500/40 text-zinc-300 rounded-lg transition"
                title="Copy Secret Token"
              >
                <Lock className="w-3.5 h-3.5 text-amber-400" />
                <span>{copiedSecret ? 'Secret Copied!' : 'Copy Session Key'}</span>
              </button>
            )}

            <button
              onClick={() => setShowDeleteModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono bg-rose-500/10 border border-rose-500/30 hover:bg-rose-500/20 text-rose-400 rounded-lg transition"
              title="Purge & Destroy Session"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Purge Session</span>
            </button>
          </div>
        </div>

        {/* METRICS ROW */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <div className="bg-black/40 p-3 rounded-xl border border-white/5">
            <div className="text-[10px] font-mono text-zinc-400 uppercase">Evidence Files</div>
            <div className="text-lg font-mono font-bold text-white">{details.evidence.length}</div>
          </div>
          <div className="bg-black/40 p-3 rounded-xl border border-white/5">
            <div className="text-[10px] font-mono text-zinc-400 uppercase">Integrity Hashes</div>
            <div className="text-lg font-mono font-bold text-emerald-400">{details.hashes.length}</div>
          </div>
          <div className="bg-black/40 p-3 rounded-xl border border-white/5">
            <div className="text-[10px] font-mono text-zinc-400 uppercase">Pipeline Stages</div>
            <div className="text-lg font-mono font-bold text-amber-400">{details.stages.length}</div>
          </div>
          <div className="bg-black/40 p-3 rounded-xl border border-white/5">
            <div className="text-[10px] font-mono text-zinc-400 uppercase">Extracted Artifacts</div>
            <div className="text-lg font-mono font-bold text-cyan-400">{details.artifacts.length}</div>
          </div>
          <div className="bg-black/40 p-3 rounded-xl border border-white/5">
            <div className="text-[10px] font-mono text-zinc-400 uppercase">Timeline Events</div>
            <div className="text-lg font-mono font-bold text-purple-400">{details.timeline.length}</div>
          </div>
          <div className="bg-black/40 p-3 rounded-xl border border-white/5">
            <div className="text-[10px] font-mono text-zinc-400 uppercase">Findings</div>
            <div className={`text-lg font-mono font-bold ${details.findings.length > 0 ? 'text-rose-400' : 'text-zinc-400'}`}>
              {details.findings.length}
            </div>
          </div>
        </div>
      </div>

      {/* CREATIVE WORKSPACE SEGMENTED NAVIGATION (NO SCROLLBAR) */}
      <nav className="bg-[#090b11]/90 p-1.5 rounded-2xl border border-white/10 backdrop-blur-xl shadow-2xl">
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-1.5">
          {[
            { id: 'overview', label: 'Overview', icon: <Activity className="w-3.5 h-3.5" />, count: null },
            { id: 'evidence', label: 'Evidence', icon: <Upload className="w-3.5 h-3.5" />, count: details.evidence.length },
            { id: 'telemetry', label: 'Telemetry', icon: <Cpu className="w-3.5 h-3.5" />, count: details.stages.length },
            { id: 'artifacts', label: 'Artifacts', icon: <Layers className="w-3.5 h-3.5" />, count: details.artifacts.length },
            { id: 'timeline', label: 'Timeline', icon: <Clock className="w-3.5 h-3.5" />, count: details.timeline.length },
            { id: 'findings', label: 'Findings', icon: <AlertTriangle className="w-3.5 h-3.5" />, count: details.findings.length },
            { id: 'report', label: 'Report', icon: <FileText className="w-3.5 h-3.5" />, count: details.report ? '✓' : null },
            { id: 'audit', label: 'Audit Log', icon: <Database className="w-3.5 h-3.5" />, count: details.audit_logs.length },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`relative flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl transition-all duration-200 text-xs font-mono font-medium select-none cursor-pointer ${
                  isActive
                    ? 'bg-gradient-to-r from-amber-500 via-amber-400 to-amber-500 text-black font-bold shadow-[0_0_20px_rgba(245,158,11,0.35)] scale-[1.02]'
                    : 'text-zinc-400 hover:text-zinc-100 hover:bg-white/[0.06]'
                }`}
              >
                <span className={isActive ? 'text-black' : 'text-zinc-400'}>
                  {tab.icon}
                </span>
                <span className="truncate">{tab.label}</span>
                {tab.count !== null && (
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded-md font-mono font-bold leading-none ${
                      isActive
                        ? 'bg-black text-amber-400 shadow-sm'
                        : 'bg-white/10 text-zinc-400'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* ======================================================== */}
      {/* TAB 1: OVERVIEW */}
      {/* ======================================================== */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Action Card */}
            <GlassCard variant="amber" className="space-y-4">
              <div className="flex items-center gap-2 text-amber-400 font-heading text-sm uppercase font-bold">
                <Terminal className="w-4 h-4" /> Next Recommended Action
              </div>

              {details.evidence.length === 0 ? (
                <div className="space-y-3">
                  <p className="text-xs text-zinc-300 font-sans">
                    No evidence registered yet. Upload digital evidence files (images, PDFs, documents, archives, logs) to begin analysis.
                  </p>
                  <button
                    onClick={() => setActiveTab('evidence')}
                    className="w-full py-2.5 bg-amber-500 hover:bg-amber-400 text-black font-heading font-bold text-xs uppercase rounded-xl transition flex items-center justify-center gap-2"
                  >
                    <Upload className="w-4 h-4" /> Go to Evidence Intake
                  </button>
                </div>
              ) : pendingEvidenceCount > 0 ? (
                <div className="space-y-3">
                  <p className="text-xs text-zinc-300 font-sans">
                    {pendingEvidenceCount} new evidence item{pendingEvidenceCount > 1 ? 's' : ''} awaiting forensic examination in the read-only vault.
                  </p>
                  <button
                    onClick={handleStartExamination}
                    disabled={processing}
                    className="w-full py-2.5 bg-amber-500 hover:bg-amber-400 text-black font-heading font-bold text-xs uppercase rounded-xl transition flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer shadow-[0_0_15px_rgba(245,158,11,0.25)]"
                  >
                    <Cpu className="w-4 h-4" /> {processing ? 'Examining Pending Evidence...' : `Run Examination (${pendingEvidenceCount} Pending)`}
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-xs text-zinc-300 font-sans">
                    All {details.evidence.length} evidence items examined! Review extracted artifacts, inspect findings, or generate a cryptographically sealed PDF report.
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setActiveTab('findings')}
                      className="flex-1 py-2 bg-zinc-800 hover:bg-zinc-700 text-white font-mono text-xs rounded-xl border border-white/10"
                    >
                      View Findings
                    </button>
                    <button
                      onClick={handleGenerateReport}
                      disabled={generatingReport}
                      className="flex-1 py-2 bg-amber-500 hover:bg-amber-400 text-black font-heading font-bold text-xs uppercase rounded-xl transition disabled:opacity-50"
                    >
                      {generatingReport ? 'Compiling...' : 'Generate Report'}
                    </button>
                  </div>
                </div>
              )}
            </GlassCard>

            {/* Evidence Summary Card */}
            <GlassCard variant="default" className="space-y-3 lg:col-span-2">
              <div className="flex items-center justify-between">
                <div className="font-heading text-sm font-bold text-white uppercase flex items-center gap-2">
                  <Fingerprint className="w-4 h-4 text-emerald-400" /> Preserved Evidence Registry
                </div>
                <button
                  onClick={() => setActiveTab('evidence')}
                  className="text-xs font-mono text-amber-400 hover:underline flex items-center gap-1"
                >
                  Manage Evidence <ChevronRight className="w-3 h-3" />
                </button>
              </div>

              {details.evidence.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono text-zinc-500">
                  No evidence files uploaded to the read-only vault.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {details.evidence.map((ev) => (
                    <div
                      key={ev.evidence_id}
                      className="bg-black/50 p-3 rounded-xl border border-white/5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono"
                    >
                      <div>
                        <div className="font-bold text-white flex items-center gap-2">
                          <span>{ev.original_filename}</span>
                          <span className="text-[10px] text-zinc-400">({(ev.size_bytes / 1024).toFixed(1)} KB)</span>
                        </div>
                        <div className="text-[10px] text-emerald-400 break-all mt-0.5">
                          SHA-256: {ev.primary_sha256}
                        </div>
                      </div>
                      <StatusBadge status={ev.processing_status} size="sm" />
                    </div>
                  ))}
                </div>
              )}
            </GlassCard>
          </div>

          {/* Pipeline Stage Matrix */}
          <GlassCard variant="default" className="space-y-4">
            <div className="font-heading text-sm font-bold text-white uppercase flex items-center gap-2">
              <Cpu className="w-4 h-4 text-amber-400" /> Forensic Engine Execution Checklist
            </div>

            {details.stages.length === 0 ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                Pipeline has not yet executed against registered evidence.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {details.stages.map((stage) => (
                  <div key={stage.stage_id} className="bg-black/50 p-3 rounded-xl border border-white/5 space-y-1.5 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{stage.tool_name}</span>
                      <StatusBadge status={stage.status} size="sm" />
                    </div>
                    <div className="text-[10px] text-zinc-400 flex items-center justify-between">
                      <span>Version: {stage.tool_version}</span>
                      <span>{stage.duration_ms !== undefined ? `${stage.duration_ms}ms` : '0ms'}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </GlassCard>
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 2: EVIDENCE INTAKE */}
      {/* ======================================================== */}
      {activeTab === 'evidence' && (
        <div className="space-y-6">
          {/* Dropzone */}
          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-amber-500/40 hover:border-amber-400 bg-amber-500/5 hover:bg-amber-500/10 rounded-2xl p-8 sm:p-12 text-center cursor-pointer transition space-y-4"
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => handleFileUpload(e.target.files)}
              className="hidden"
            />
            <div className="w-20 h-20 rounded-2xl bg-[#0a0d14] border border-amber-500/30 p-3 flex items-center justify-center text-amber-400 mx-auto shadow-[0_0_20px_rgba(245,158,11,0.2)] overflow-hidden">
              <img src="/logo.svg" alt="Upload Evidence" className="w-full h-full object-contain rounded-xl transform scale-115" />
            </div>
            <div className="space-y-1">
              <div className="font-heading text-lg font-bold text-white uppercase">
                {uploading ? 'INGESTING & STREAM-HASHING EVIDENCE...' : 'SELECT OR DROP EVIDENCE FILE'}
              </div>
              <p className="text-xs text-zinc-400 font-mono">
                Supported: Images (JPEG, PNG, TIFF), Documents (PDF), Office (DOCX, XLSX, PPTX), Archives (ZIP, TAR, GZ), Logs (EVTX, Syslog, Apache), Binaries (PE, ELF)
              </p>
              <p className="text-[10px] text-amber-400 font-mono">Max File Size: 50 MB per intake | Read-Only Vault Preservation</p>
            </div>
          </div>

          {/* Feedback alerts */}
          {uploadError && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}

          {uploadSuccess && (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              <span>{uploadSuccess}</span>
            </div>
          )}

          {/* Evidence Inventory Table */}
          <GlassCard variant="default" className="space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="font-heading text-sm font-bold text-white uppercase flex items-center gap-2">
                <Database className="w-4 h-4 text-amber-400" /> Read-Only Evidence Vault Inventory
              </div>
              <div className="text-xs font-mono text-zinc-400">{details.evidence.length} Total Registered Items</div>
            </div>

            {details.evidence.length === 0 ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                No evidence files registered in this investigation.
              </div>
            ) : (
              <div className="space-y-4">
                {details.evidence.map((ev) => (
                  <div key={ev.evidence_id} className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-3">
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-white/5 pb-2">
                      <div className="flex items-center gap-2 font-mono text-xs">
                        <span className="font-bold text-white text-sm">{ev.original_filename}</span>
                        <span className="text-zinc-400">({(ev.size_bytes / 1024).toFixed(2)} KB)</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <StatusBadge status={ev.preservation_status} size="sm" />
                        <StatusBadge status={ev.processing_status} size="sm" />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px] font-mono">
                      <div className="bg-black/40 p-2.5 rounded-lg border border-white/5">
                        <span className="text-[10px] text-zinc-500 uppercase block">Authoritative SHA-256</span>
                        <span className="text-emerald-400 font-bold break-all">{ev.primary_sha256}</span>
                      </div>
                      <div className="bg-black/40 p-2.5 rounded-lg border border-white/5">
                        <span className="text-[10px] text-zinc-500 uppercase block">Compatibility SHA-1</span>
                        <span className="text-zinc-300 break-all">{ev.sha1}</span>
                      </div>
                      <div className="bg-black/40 p-2.5 rounded-lg border border-white/5">
                        <span className="text-[10px] text-zinc-500 uppercase block">Compatibility MD5</span>
                        <span className="text-zinc-300 break-all">{ev.md5}</span>
                      </div>
                    </div>

                    <div className="text-[10px] font-mono text-zinc-500 flex flex-wrap gap-4">
                      <span>Detected MIME: {ev.detected_mime}</span>
                      <span>Acquired: {new Date(ev.acquisition_timestamp).toUTCString()}</span>
                      <span>Storage Path: {ev.storage_path}</span>
                    </div>
                  </div>
                ))}

                <div className="pt-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-t border-white/5">
                  <div className="text-xs font-mono text-zinc-400">
                    {pendingEvidenceCount > 0 ? (
                      <span className="text-amber-400 font-bold flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 animate-pulse" />
                        {pendingEvidenceCount} item{pendingEvidenceCount > 1 ? 's' : ''} awaiting examination
                      </span>
                    ) : (
                      <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5" /> All {details.evidence.length} items examined
                      </span>
                    )}
                  </div>
                  <button
                    onClick={handleStartExamination}
                    disabled={processing || pendingEvidenceCount === 0}
                    className="px-6 py-3 bg-amber-500 hover:bg-amber-400 text-black font-heading font-bold text-xs uppercase tracking-wider rounded-xl shadow-[0_0_20px_rgba(245,158,11,0.3)] transition disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                  >
                    {processing
                      ? 'Processing Pipeline...'
                      : pendingEvidenceCount > 0
                      ? `Run Forensic Examination (${pendingEvidenceCount} Pending)`
                      : 'All Evidence Examined'}
                  </button>
                </div>
              </div>
            )}
          </GlassCard>
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 3: PIPELINE TELEMETRY */}
      {/* ======================================================== */}
      {activeTab === 'telemetry' && (
        <div className="space-y-6">
          <GlassCard variant="default" className="space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="font-heading text-sm font-bold text-white uppercase flex items-center gap-2">
                <Cpu className="w-4 h-4 text-amber-400" /> Modular Engine Execution Telemetry
              </div>
              <button
                onClick={() => fetchDetails(false)}
                className="text-xs font-mono text-amber-400 hover:underline flex items-center gap-1"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Refresh Telemetry
              </button>
            </div>

            {details.stages.length === 0 ? (
              <div className="py-12 text-center text-xs font-mono text-zinc-500 space-y-3">
                <Cpu className="w-8 h-8 mx-auto text-zinc-600" />
                <p>No stage telemetry recorded. Run the forensic examination to dispatch the pipeline.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {details.stages.map((stg) => (
                  <div key={stg.stage_id} className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-2 text-xs font-mono">
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-amber-400 font-bold">#{stg.stage_order}</span>
                        <span className="font-bold text-white text-sm">{stg.tool_name}</span>
                        <span className="text-[10px] text-zinc-500">v{stg.tool_version}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-zinc-400">{stg.duration_ms !== undefined ? `${stg.duration_ms} ms` : ''}</span>
                        <StatusBadge status={stg.status} size="sm" />
                      </div>
                    </div>

                    {/* Metadata JSON */}
                    {stg.execution_metadata && Object.keys(stg.execution_metadata).length > 0 && (
                      <div className="rounded-lg overflow-hidden border border-white/5 bg-black/80">
                        <pre className="p-3 text-[10px] text-amber-300 font-mono whitespace-pre-wrap break-all max-h-48 overflow-y-auto overflow-x-hidden leading-relaxed select-text">
                          {JSON.stringify(stg.execution_metadata, null, 2)}
                        </pre>
                      </div>
                    )}

                    {stg.warnings && stg.warnings.length > 0 && (
                      <div className="text-[11px] text-amber-400 space-y-1">
                        {stg.warnings.map((w, idx) => (
                          <div key={idx}>⚠️ {w}</div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </GlassCard>
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 4: EXTRACTED ARTIFACTS */}
      {/* ======================================================== */}
      {activeTab === 'artifacts' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-zinc-400 absolute left-3.5 top-3.5" />
              <input
                type="text"
                placeholder="Search artifacts by name, type, or extracted payload contents..."
                value={artifactSearch}
                onChange={(e) => setArtifactSearch(e.target.value)}
                className="w-full bg-black/60 border border-white/10 focus:border-amber-500 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white font-mono focus:outline-none"
              />
            </div>
            <select
              value={artifactCategory}
              onChange={(e) => setArtifactCategory(e.target.value)}
              className="bg-black/60 border border-white/10 text-zinc-300 text-xs rounded-xl px-3 py-2.5 font-mono focus:outline-none focus:border-amber-500"
            >
              <option value="ALL">All Categories</option>
              <option value="IDENTIFICATION">Identification</option>
              <option value="METADATA">Metadata / EXIF</option>
              <option value="STRUCTURE">Structure / Archives</option>
              <option value="STRING">Strings & IOCs</option>
              <option value="LOG_RECORD">Log Records</option>
            </select>
          </div>

          {filteredArtifacts.length === 0 ? (
            <div className="py-12 text-center text-xs font-mono text-zinc-500">
              No artifacts match your search and category filter.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {filteredArtifacts.map((art) => (
                <GlassCard key={art.artifact_id} variant="default" className="space-y-3 overflow-hidden">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-white/5 pb-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-amber-400 font-bold">{art.artifact_id}</span>
                      <span className="font-heading text-sm font-bold text-white uppercase">{art.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono bg-zinc-800 text-zinc-300 px-2 py-0.5 rounded">
                        {art.category}
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500">
                        {new Date(art.extracted_at).toLocaleTimeString()}
                      </span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(JSON.stringify(art.data_payload, null, 2));
                          setCopiedArtifactId(art.artifact_id);
                          setTimeout(() => setCopiedArtifactId(null), 2000);
                        }}
                        className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 text-zinc-300 hover:text-amber-400 border border-white/10 transition cursor-pointer"
                        title="Copy JSON Payload"
                      >
                        {copiedArtifactId === art.artifact_id ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span className="text-emerald-400">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {art.raw_offset_range && (
                    <div className="text-[10px] font-mono text-cyan-400">Byte Range: {art.raw_offset_range}</div>
                  )}

                  <div className="rounded-xl overflow-hidden border border-white/5 bg-black/80">
                    <pre className="p-3.5 text-[11px] text-zinc-300 font-mono whitespace-pre-wrap break-all max-h-64 overflow-y-auto overflow-x-hidden leading-relaxed select-text">
                      {JSON.stringify(art.data_payload, null, 2)}
                    </pre>
                  </div>
                </GlassCard>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 5: NORMALIZED TIMELINE */}
      {/* ======================================================== */}
      {activeTab === 'timeline' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="text-xs font-mono text-zinc-400">
              Showing {filteredTimeline.length} Chronological Events
            </div>
            <select
              value={timelineConfidence}
              onChange={(e) => setTimelineConfidence(e.target.value)}
              className="bg-black/60 border border-white/10 text-zinc-300 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none"
            >
              <option value="ALL">All Confidences</option>
              <option value="DEFINITIVE">Definitive</option>
              <option value="HEURISTIC">Heuristic</option>
              <option value="INFERRED">Inferred</option>
            </select>
          </div>

          {filteredTimeline.length === 0 ? (
            <div className="py-12 text-center text-xs font-mono text-zinc-500">
              No timestamped events reconstructed.
            </div>
          ) : (
            <div className="relative border-l-2 border-amber-500/30 ml-4 pl-6 space-y-6">
              {filteredTimeline.map((tle) => (
                <div key={tle.event_id} className="relative space-y-1">
                  {/* Dot */}
                  <div className="absolute -left-[31px] top-1 w-3 h-3 rounded-full bg-amber-500 border-2 border-black" />

                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-amber-400 font-bold">{tle.timestamp_utc}</span>
                    <span className="text-[10px] font-mono bg-zinc-800 text-zinc-300 px-2 py-0.5 rounded">
                      {tle.event_type}
                    </span>
                    <StatusBadge status={tle.confidence} size="sm" />
                  </div>

                  <p className="text-xs text-zinc-200 font-sans">{tle.description}</p>
                  <div className="text-[10px] font-mono text-zinc-500">
                    Source: {tle.source_parser} ({tle.source_field}) | Raw: {tle.timestamp_raw}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 6: FORENSIC FINDINGS */}
      {/* ======================================================== */}
      {activeTab === 'findings' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="text-xs font-mono text-zinc-400">
              {filteredFindings.length} Analytic Findings Correlated
            </div>
            <select
              value={findingSeverity}
              onChange={(e) => setFindingSeverity(e.target.value)}
              className="bg-black/60 border border-white/10 text-zinc-300 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="py-12 text-center text-xs font-mono text-zinc-500">
              No findings generated yet. Run examination to correlate artifacts.
            </div>
          ) : (
            <div className="space-y-4">
              {filteredFindings.map((fnd) => (
                <GlassCard
                  key={fnd.finding_id}
                  variant={fnd.severity === 'HIGH' || fnd.severity === 'CRITICAL' ? 'subtle' : 'default'}
                  className={`space-y-3 ${fnd.severity === 'HIGH' || fnd.severity === 'CRITICAL' ? 'border-rose-500/40 bg-rose-500/5' : ''
                    }`}
                >
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-white/5 pb-2">
                    <div className="flex items-center gap-2">
                      <StatusBadge status={fnd.severity} size="sm" />
                      <h3 className="font-heading text-sm font-bold text-white uppercase">{fnd.title}</h3>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-400">{fnd.category}</span>
                  </div>

                  <p className="text-xs text-zinc-200 font-sans leading-relaxed">{fnd.description}</p>

                  <div className="bg-black/50 p-3 rounded-xl border border-white/5 space-y-1.5 text-[11px] font-mono">
                    <div className="text-zinc-400">
                      <span className="text-amber-400 uppercase font-bold">Technical Rationale:</span> {fnd.technical_rationale}
                    </div>
                    <div className="text-zinc-500 text-[10px]">
                      Method: {fnd.analysis_method} | Engine: {fnd.source_module}
                    </div>
                    {fnd.limitations && (
                      <div className="text-zinc-500 text-[10px]">
                        <span className="text-zinc-400">Limitations:</span> {fnd.limitations}
                      </div>
                    )}
                  </div>

                  {/* Supporting Artifacts Provenance Links */}
                  <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono">
                    <span className="text-zinc-500 uppercase text-[10px]">Supporting Artifacts:</span>
                    {fnd.supporting_artifact_ids.map((artId) => (
                      <button
                        key={artId}
                        onClick={() => {
                          setArtifactSearch(artId);
                          setActiveTab('artifacts');
                        }}
                        className="bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded text-[10px] transition cursor-pointer flex items-center gap-1"
                      >
                        <Eye className="w-3 h-3" />
                        <span>{artId}</span>
                      </button>
                    ))}
                  </div>
                </GlassCard>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 7: EXAMINATION REPORT */}
      {/* ======================================================== */}
      {activeTab === 'report' && (
        <div className="space-y-6">
          <GlassCard variant="amber" className="space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/40 p-1.5 flex items-center justify-center overflow-hidden shadow-[0_0_20px_rgba(245,158,11,0.25)]">
                  <img src="/logo.svg" alt="Silhouette Reaper Seal" className="w-full h-full object-contain rounded-lg transform scale-115" />
                </div>
                <div>
                  <div className="font-heading text-base font-bold text-white uppercase flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-emerald-400" /> Cryptographically Sealed Examination Report
                  </div>
                  <p className="text-xs text-zinc-400 font-mono mt-0.5">
                    Formal PDF report compilation with Merkle root digest and offline/online verification seal
                  </p>
                </div>
              </div>

              <button
                onClick={handleGenerateReport}
                disabled={generatingReport}
                className="px-6 py-2.5 bg-amber-500 hover:bg-amber-400 text-black font-heading font-bold text-xs uppercase rounded-xl transition shadow-[0_0_15px_rgba(245,158,11,0.3)] disabled:opacity-50 cursor-pointer"
              >
                {generatingReport ? 'Compiling PDF...' : details.report ? 'Re-Generate Sealed Report' : 'Compile Sealed Report'}
              </button>
            </div>

            {reportError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 text-xs font-mono">
                {reportError}
              </div>
            )}

            {!details.report ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-400 space-y-2">
                <FileText className="w-8 h-8 mx-auto text-amber-400 opacity-60" />
                <p>No sealed report has been generated yet for this investigation session.</p>
                <p className="text-[11px] text-zinc-500">Click "Compile Sealed Report" above to generate the PDF.</p>
              </div>
            ) : (
              <div className="space-y-4 pt-2 animate-fadeIn">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-1">
                    <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Verification Token</span>
                    <span className="text-emerald-400 font-bold text-sm">{details.report.verification_token}</span>
                  </div>

                  <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-1">
                    <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Report Generation Timestamp (UTC)</span>
                    <span className="text-zinc-200">{new Date(details.report.generated_at).toUTCString()}</span>
                  </div>

                  <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-1 md:col-span-2">
                    <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Document SHA-256 Digest</span>
                    <span className="text-emerald-400 font-bold break-all text-[11px]">{details.report.report_sha256}</span>
                  </div>

                  <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-1 md:col-span-2">
                    <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Cryptographic Merkle Root</span>
                    <span className="text-amber-400 font-bold break-all text-[11px]">{details.report.merkle_root}</span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                  <a
                    href={`/api/v1/investigations/${investigationId}/reports/${details.report.report_id}/download`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-black font-heading font-bold text-xs uppercase tracking-wider rounded-xl shadow-[0_0_20px_rgba(16,185,129,0.3)] transition"
                  >
                    <Download className="w-4 h-4" /> Download Forensic Report PDF ({(details.report.file_size_bytes / 1024).toFixed(1)} KB)
                  </a>

                  <Link
                    href={`/verify?code=${details.report.verification_token}`}
                    className="inline-flex items-center gap-1.5 px-4 py-3 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 font-mono text-xs rounded-xl border border-white/10 hover:border-amber-500/40 transition"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-amber-400" /> Open Public Verification View
                  </Link>
                </div>
              </div>
            )}
          </GlassCard>
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 8: AUDIT TRAIL */}
      {/* ======================================================== */}
      {activeTab === 'audit' && (
        <div className="space-y-6">
          <GlassCard variant="default" className="space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="font-heading text-sm font-bold text-white uppercase flex items-center gap-2">
                <Database className="w-4 h-4 text-amber-400" /> Immutable Investigation Audit Log
              </div>
              <div className="text-xs font-mono text-zinc-400">{details.audit_logs.length} Recorded Custody Events</div>
            </div>

            <div className="space-y-2 font-mono text-xs">
              {details.audit_logs.map((log) => (
                <div
                  key={log.event_id}
                  className="bg-black/50 p-3 rounded-xl border border-white/5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-amber-400 font-bold">{log.action}</span>
                      <span className="text-[10px] text-zinc-500">[{log.actor_type}]</span>
                    </div>
                    <div className="text-[10px] text-zinc-400">
                      Object: {log.object_type} ({log.object_id})
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-zinc-500 block">{new Date(log.timestamp).toUTCString()}</span>
                    <StatusBadge status={log.result} size="sm" />
                  </div>
                </div>
              ))}
            </div>
          </GlassCard>
        </div>
      )}

      {/* DELETE / PURGE CONFIRMATION MODAL */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="glass-panel w-full max-w-md p-6 rounded-2xl border-rose-500/40 space-y-4">
            <div className="flex items-center gap-3 text-rose-400 font-heading text-base uppercase font-bold">
              <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 p-1 flex items-center justify-center overflow-hidden">
                <img src="/logo.svg" alt="Purge Session" className="w-full h-full object-contain rounded-md opacity-70" />
              </div>
              Permanently Purge Investigation?
            </div>
            <p className="text-xs text-zinc-300 font-sans leading-relaxed">
              This action will permanently zero-fill and delete all evidence binaries from the vault, erase derived artifacts, purge forensic reports, and remove all session metadata. This cannot be undone.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowDeleteModal(false)}
                className="px-4 py-2 text-xs font-mono text-zinc-400 hover:text-white rounded-lg hover:bg-white/5"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteSession}
                className="px-4 py-2 text-xs font-heading font-bold uppercase tracking-wider bg-rose-600 hover:bg-rose-500 text-white rounded-lg transition"
              >
                Confirm Permanent Purge
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function WorkspacePage() {
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
            Connecting To Secure Laboratory Vault...
          </div>
        </div>
      }
    >
      <WorkspaceContent />
    </Suspense>
  );
}
