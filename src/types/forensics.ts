export type InvestigationStatus =
  | 'CREATED'
  | 'EVIDENCE_PENDING'
  | 'EVIDENCE_REGISTERED'
  | 'QUEUED'
  | 'ACQUISITION_VERIFIED'
  | 'EXAMINATION'
  | 'ARTIFACT_EXTRACTION'
  | 'ANALYSIS'
  | 'FINDINGS_READY'
  | 'REPORT_READY'
  | 'FAILED'
  | 'CANCELLED'
  | 'EXPIRED'
  | 'DELETED';

export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type StageStatus = 'PENDING' | 'RUNNING' | 'SUCCESS' | 'WARNING' | 'FAILED' | 'SKIPPED';

export type FindingSeverity = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FindingCategory =
  | 'INTEGRITY'
  | 'FILE_ANOMALY'
  | 'EXTENSION_SPOOF'
  | 'METADATA_DISCREPANCY'
  | 'TIMESTOMP_DETECTED'
  | 'EMBEDDED_OBJECT'
  | 'SUSPICIOUS_STRING'
  | 'NETWORK_INDICATOR'
  | 'SECURITY_EVENT'
  | 'EXECUTION_EVIDENCE'
  | 'LIMITATION';

export type ConfidenceLevel = 'DEFINITIVE' | 'HEURISTIC' | 'INFERRED';

export interface InvestigationSession {
  investigation_id: string;
  session_secret_hash: string;
  created_at: string;
  expires_at: string;
  status: InvestigationStatus;
  evidence_count: number;
  retention_hours: number;
  last_activity_at: string;
}

export interface EvidenceRecord {
  evidence_id: string;
  investigation_id: string;
  original_filename: string;
  declared_mime: string;
  detected_mime: string;
  detected_extension: string;
  size_bytes: number;
  primary_sha256: string;
  sha1: string;
  md5: string;
  storage_path: string;
  preservation_status: 'PRESERVED_RO' | 'TAMPER_DETECTED' | 'PURGED';
  processing_status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  acquisition_timestamp: string;
  upload_timestamp: string;
}

export interface EvidenceHash {
  hash_id: string;
  evidence_id: string;
  algorithm: 'SHA-256' | 'SHA-1' | 'MD5' | 'ENTROPY';
  hash_value: string;
  purpose: 'PRIMARY_INTEGRITY' | 'COMPATIBILITY' | 'ANALYTICAL';
  calculated_at: string;
}

export interface ProcessingJob {
  job_id: string;
  evidence_id: string;
  investigation_id: string;
  status: JobStatus;
  queued_at: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
}

export interface ProcessingStage {
  stage_id: string;
  job_id: string;
  evidence_id: string;
  stage_name: string;
  stage_order: number;
  tool_name: string;
  tool_version: string;
  status: StageStatus;
  start_time: string;
  end_time?: string;
  duration_ms?: number;
  execution_metadata: Record<string, any>;
  warnings: string[];
  errors: string[];
}

export interface ForensicArtifact {
  artifact_id: string;
  evidence_id: string;
  investigation_id: string;
  stage_id: string;
  artifact_type: string;
  name: string;
  category: 'IDENTIFICATION' | 'METADATA' | 'STRUCTURE' | 'STRING' | 'ARCHIVE_ENTRY' | 'LOG_RECORD' | 'INDICATOR' | 'RAW';
  data_payload: Record<string, any>;
  raw_offset_range?: string;
  extracted_at: string;
}

export interface TimelineEvent {
  event_id: string;
  evidence_id: string;
  investigation_id: string;
  artifact_id?: string;
  timestamp_utc: string;
  timestamp_raw: string;
  timestamp_precision: 'MILLISECOND' | 'SECOND' | 'MINUTE' | 'DAY' | 'UNCERTAIN';
  timezone_offset: string;
  event_type: string;
  source_parser: string;
  source_field: string;
  description: string;
  confidence: ConfidenceLevel;
}

export interface ForensicFinding {
  finding_id: string;
  evidence_id: string;
  investigation_id: string;
  title: string;
  category: FindingCategory;
  severity: FindingSeverity;
  description: string;
  technical_rationale: string;
  analysis_method: string;
  source_module: string;
  supporting_artifact_ids: string[];
  limitations?: string;
  created_at: string;
}

export interface AuditEvent {
  event_id: string;
  investigation_id: string;
  timestamp: string;
  actor_type: 'ANONYMOUS_SESSION' | 'SYSTEM_WORKER' | 'REPORT_GENERATOR' | 'SYSTEM_CRON';
  action: string;
  object_type: string;
  object_id: string;
  result: 'SUCCESS' | 'FAILURE' | 'WARNING';
  metadata: Record<string, any>;
}

export interface ForensicReport {
  report_id: string;
  investigation_id: string;
  report_sha256: string;
  verification_token: string;
  merkle_root: string;
  generated_at: string;
  expires_at: string; // 7-day retention expiration timestamp
  session_purged?: boolean; // True if raw evidence vault was purged while report proof persists
  storage_path: string;
  file_size_bytes: number;
  report_manifest: {
    investigation_id: string;
    generated_at: string;
    evidence_count: number;
    artifact_count: number;
    finding_count: number;
    timeline_event_count: number;
    tools_used: { name: string; version: string }[];
  };
}

export interface InvestigationFullDetails {
  session: InvestigationSession;
  evidence: EvidenceRecord[];
  hashes: EvidenceHash[];
  jobs: ProcessingJob[];
  stages: ProcessingStage[];
  artifacts: ForensicArtifact[];
  timeline: TimelineEvent[];
  findings: ForensicFinding[];
  audit_logs: AuditEvent[];
  report?: ForensicReport;
}
