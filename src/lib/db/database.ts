import fs from 'fs';
import path from 'path';
import { DatabaseSync } from 'node:sqlite';
import {
  InvestigationSession,
  EvidenceRecord,
  EvidenceHash,
  ProcessingJob,
  ProcessingStage,
  ForensicArtifact,
  TimelineEvent,
  ForensicFinding,
  AuditEvent,
  ForensicReport,
  InvestigationFullDetails,
} from '@/types/forensics';

const STORAGE_ROOT = path.join(process.cwd(), 'storage');
const DB_PATH = path.join(STORAGE_ROOT, 'database', 'forensics.sqlite');

// Ensure base storage paths exist
function ensureStoragePaths() {
  const dirs = [
    STORAGE_ROOT,
    path.join(STORAGE_ROOT, 'database'),
    path.join(STORAGE_ROOT, 'evidence_vault'),
    path.join(STORAGE_ROOT, 'artifacts_store'),
    path.join(STORAGE_ROOT, 'reports_registry'),
  ];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }
}

let dbInstance: DatabaseSync | null = null;

export function getDb(): DatabaseSync {
  if (!dbInstance) {
    ensureStoragePaths();
    dbInstance = new DatabaseSync(DB_PATH);
    dbInstance.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
    `);
    initializeSchema(dbInstance);
  }
  return dbInstance;
}

function initializeSchema(db: DatabaseSync) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS investigations (
      investigation_id TEXT PRIMARY KEY,
      session_secret_hash TEXT NOT NULL,
      status TEXT NOT NULL,
      evidence_count INTEGER DEFAULT 0,
      retention_hours INTEGER DEFAULT 24,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_activity_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence (
      evidence_id TEXT PRIMARY KEY,
      investigation_id TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      declared_mime TEXT NOT NULL,
      detected_mime TEXT NOT NULL,
      detected_extension TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      primary_sha256 TEXT NOT NULL,
      sha1 TEXT NOT NULL,
      md5 TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      preservation_status TEXT NOT NULL,
      processing_status TEXT NOT NULL,
      acquisition_timestamp TEXT NOT NULL,
      upload_timestamp TEXT NOT NULL,
      FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS evidence_hashes (
      hash_id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL,
      algorithm TEXT NOT NULL,
      hash_value TEXT NOT NULL,
      purpose TEXT NOT NULL,
      calculated_at TEXT NOT NULL,
      FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS processing_jobs (
      job_id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      status TEXT NOT NULL,
      queued_at TEXT NOT NULL,
      started_at TEXT,
      finished_at TEXT,
      error_message TEXT,
      FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS processing_stages (
      stage_id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL,
      evidence_id TEXT NOT NULL,
      stage_name TEXT NOT NULL,
      stage_order INTEGER NOT NULL,
      tool_name TEXT NOT NULL,
      tool_version TEXT NOT NULL,
      status TEXT NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT,
      duration_ms INTEGER,
      execution_metadata TEXT,
      warnings TEXT,
      errors TEXT,
      FOREIGN KEY (job_id) REFERENCES processing_jobs(job_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS artifacts (
      artifact_id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      stage_id TEXT NOT NULL,
      artifact_type TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      data_payload TEXT NOT NULL,
      raw_offset_range TEXT,
      extracted_at TEXT NOT NULL,
      FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS timeline_events (
      event_id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      artifact_id TEXT,
      timestamp_utc TEXT NOT NULL,
      timestamp_raw TEXT NOT NULL,
      timestamp_precision TEXT NOT NULL,
      timezone_offset TEXT NOT NULL,
      event_type TEXT NOT NULL,
      source_parser TEXT NOT NULL,
      source_field TEXT NOT NULL,
      description TEXT NOT NULL,
      confidence TEXT NOT NULL,
      FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS findings (
      finding_id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT NOT NULL,
      technical_rationale TEXT NOT NULL,
      analysis_method TEXT NOT NULL,
      source_module TEXT NOT NULL,
      supporting_artifact_ids TEXT NOT NULL,
      limitations TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      event_id TEXT PRIMARY KEY,
      investigation_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      actor_type TEXT NOT NULL,
      action TEXT NOT NULL,
      object_type TEXT NOT NULL,
      object_id TEXT NOT NULL,
      result TEXT NOT NULL,
      metadata TEXT,
      FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reports (
      report_id TEXT PRIMARY KEY,
      investigation_id TEXT NOT NULL,
      report_sha256 TEXT NOT NULL,
      verification_token TEXT UNIQUE NOT NULL,
      merkle_root TEXT NOT NULL,
      generated_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      file_size_bytes INTEGER NOT NULL,
      report_manifest TEXT NOT NULL,
      session_purged INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_artifacts_investigation ON artifacts(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_timeline_investigation ON timeline_events(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_audit_investigation ON audit_events(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_reports_verification ON reports(verification_token);
  `);

  // Ensure reports table has expires_at and session_purged columns and no foreign key cascade
  try {
    const fkList = db.prepare(`PRAGMA foreign_key_list(reports)`).all() as any[];
    const reportCols = db.prepare(`PRAGMA table_info(reports)`).all() as any[];
    const colNames = reportCols.map((c) => c.name);

    if (fkList.length > 0 || !colNames.includes('expires_at') || !colNames.includes('session_purged')) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS reports_v2 (
          report_id TEXT PRIMARY KEY,
          investigation_id TEXT NOT NULL,
          report_sha256 TEXT NOT NULL,
          verification_token TEXT UNIQUE NOT NULL,
          merkle_root TEXT NOT NULL,
          generated_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          storage_path TEXT NOT NULL,
          file_size_bytes INTEGER NOT NULL,
          report_manifest TEXT NOT NULL,
          session_purged INTEGER DEFAULT 0
        );
      `);

      // Copy existing rows if any
      try {
        db.exec(`
          INSERT OR IGNORE INTO reports_v2 (
            report_id, investigation_id, report_sha256, verification_token,
            merkle_root, generated_at, expires_at, storage_path, file_size_bytes, report_manifest, session_purged
          )
          SELECT 
            report_id, investigation_id, report_sha256, verification_token,
            merkle_root, generated_at, 
            datetime(generated_at, '+7 days'),
            storage_path, file_size_bytes, report_manifest,
            0
          FROM reports;
        `);
      } catch (copyErr) {}

      db.exec(`
        DROP TABLE IF EXISTS reports;
        ALTER TABLE reports_v2 RENAME TO reports;
      `);
    }

    db.exec(`CREATE INDEX IF NOT EXISTS idx_reports_verification ON reports(verification_token);`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_reports_expires ON reports(expires_at);`);
  } catch (e) {
    // Migration check ignore
  }
}

export class ForensicRepository {
  // --- Investigations ---
  static createInvestigation(session: InvestigationSession): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO investigations (
        investigation_id, session_secret_hash, status, evidence_count,
        retention_hours, created_at, expires_at, last_activity_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      session.investigation_id,
      session.session_secret_hash,
      session.status,
      session.evidence_count,
      session.retention_hours,
      session.created_at,
      session.expires_at,
      session.last_activity_at
    );
  }

  static getInvestigation(id: string): InvestigationSession | null {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM investigations WHERE investigation_id = ?`);
    const row = stmt.get(id) as any;
    if (!row) return null;

    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
      this.deleteInvestigation(id);
      return null;
    }
    return {
      investigation_id: row.investigation_id,
      session_secret_hash: row.session_secret_hash,
      status: row.status,
      evidence_count: Number(row.evidence_count),
      retention_hours: Number(row.retention_hours),
      created_at: row.created_at,
      expires_at: row.expires_at,
      last_activity_at: row.last_activity_at,
    };
  }

  static updateInvestigationStatus(id: string, status: string): void {
    const db = getDb();
    const now = new Date().toISOString();
    const stmt = db.prepare(`
      UPDATE investigations 
      SET status = ?, last_activity_at = ? 
      WHERE investigation_id = ?
    `);
    stmt.run(status, now, id);
  }

  static incrementEvidenceCount(id: string): void {
    const db = getDb();
    const now = new Date().toISOString();
    const stmt = db.prepare(`
      UPDATE investigations 
      SET evidence_count = evidence_count + 1, last_activity_at = ? 
      WHERE investigation_id = ?
    `);
    stmt.run(now, id);
  }

  // --- Evidence ---
  static createEvidence(evidence: EvidenceRecord): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO evidence (
        evidence_id, investigation_id, original_filename, declared_mime,
        detected_mime, detected_extension, size_bytes, primary_sha256,
        sha1, md5, storage_path, preservation_status, processing_status,
        acquisition_timestamp, upload_timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      evidence.evidence_id,
      evidence.investigation_id,
      evidence.original_filename,
      evidence.declared_mime,
      evidence.detected_mime,
      evidence.detected_extension,
      evidence.size_bytes,
      evidence.primary_sha256,
      evidence.sha1,
      evidence.md5,
      evidence.storage_path,
      evidence.preservation_status,
      evidence.processing_status,
      evidence.acquisition_timestamp,
      evidence.upload_timestamp
    );
  }

  static getEvidenceByInvestigation(investigationId: string): EvidenceRecord[] {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM evidence WHERE investigation_id = ?`);
    const rows = stmt.all(investigationId) as any[];
    return rows.map((r) => ({
      evidence_id: r.evidence_id,
      investigation_id: r.investigation_id,
      original_filename: r.original_filename,
      declared_mime: r.declared_mime,
      detected_mime: r.detected_mime,
      detected_extension: r.detected_extension,
      size_bytes: Number(r.size_bytes),
      primary_sha256: r.primary_sha256,
      sha1: r.sha1,
      md5: r.md5,
      storage_path: r.storage_path,
      preservation_status: r.preservation_status,
      processing_status: r.processing_status,
      acquisition_timestamp: r.acquisition_timestamp,
      upload_timestamp: r.upload_timestamp,
    }));
  }

  static getEvidence(evidenceId: string): EvidenceRecord | null {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM evidence WHERE evidence_id = ?`);
    const r = stmt.get(evidenceId) as any;
    if (!r) return null;
    return {
      evidence_id: r.evidence_id,
      investigation_id: r.investigation_id,
      original_filename: r.original_filename,
      declared_mime: r.declared_mime,
      detected_mime: r.detected_mime,
      detected_extension: r.detected_extension,
      size_bytes: Number(r.size_bytes),
      primary_sha256: r.primary_sha256,
      sha1: r.sha1,
      md5: r.md5,
      storage_path: r.storage_path,
      preservation_status: r.preservation_status,
      processing_status: r.processing_status,
      acquisition_timestamp: r.acquisition_timestamp,
      upload_timestamp: r.upload_timestamp,
    };
  }

  static updateEvidenceProcessingStatus(evidenceId: string, status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED'): void {
    const db = getDb();
    const stmt = db.prepare(`UPDATE evidence SET processing_status = ? WHERE evidence_id = ?`);
    stmt.run(status, evidenceId);
  }

  // --- Hashes ---
  static createEvidenceHash(hash: EvidenceHash): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO evidence_hashes (
        hash_id, evidence_id, algorithm, hash_value, purpose, calculated_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(hash.hash_id, hash.evidence_id, hash.algorithm, hash.hash_value, hash.purpose, hash.calculated_at);
  }

  static getHashesByEvidence(evidenceId: string): EvidenceHash[] {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM evidence_hashes WHERE evidence_id = ?`);
    return stmt.all(evidenceId) as any[];
  }

  // --- Processing Jobs & Stages ---
  static createJob(job: ProcessingJob): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO processing_jobs (
        job_id, evidence_id, investigation_id, status, queued_at, started_at, finished_at, error_message
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      job.job_id,
      job.evidence_id,
      job.investigation_id,
      job.status,
      job.queued_at,
      job.started_at || null,
      job.finished_at || null,
      job.error_message || null
    );
  }

  static updateJobStatus(jobId: string, status: string, finishedAt?: string, errorMsg?: string): void {
    const db = getDb();
    const stmt = db.prepare(`
      UPDATE processing_jobs
      SET status = ?, finished_at = ?, error_message = ?
      WHERE job_id = ?
    `);
    stmt.run(status, finishedAt || null, errorMsg || null, jobId);
  }

  static createStage(stage: ProcessingStage): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO processing_stages (
        stage_id, job_id, evidence_id, stage_name, stage_order,
        tool_name, tool_version, status, start_time, end_time,
        duration_ms, execution_metadata, warnings, errors
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      stage.stage_id,
      stage.job_id,
      stage.evidence_id,
      stage.stage_name,
      stage.stage_order,
      stage.tool_name,
      stage.tool_version,
      stage.status,
      stage.start_time,
      stage.end_time || null,
      stage.duration_ms || null,
      JSON.stringify(stage.execution_metadata || {}),
      JSON.stringify(stage.warnings || []),
      JSON.stringify(stage.errors || [])
    );
  }

  static getStagesByEvidence(evidenceId: string): ProcessingStage[] {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM processing_stages WHERE evidence_id = ? ORDER BY stage_order ASC`);
    const rows = stmt.all(evidenceId) as any[];
    return rows.map((r) => ({
      stage_id: r.stage_id,
      job_id: r.job_id,
      evidence_id: r.evidence_id,
      stage_name: r.stage_name,
      stage_order: Number(r.stage_order),
      tool_name: r.tool_name,
      tool_version: r.tool_version,
      status: r.status,
      start_time: r.start_time,
      end_time: r.end_time,
      duration_ms: r.duration_ms ? Number(r.duration_ms) : undefined,
      execution_metadata: JSON.parse(r.execution_metadata || '{}'),
      warnings: JSON.parse(r.warnings || '[]'),
      errors: JSON.parse(r.errors || '[]'),
    }));
  }

  // --- Artifacts ---
  static createArtifact(artifact: ForensicArtifact): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO artifacts (
        artifact_id, evidence_id, investigation_id, stage_id,
        artifact_type, name, category, data_payload, raw_offset_range, extracted_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      artifact.artifact_id,
      artifact.evidence_id,
      artifact.investigation_id,
      artifact.stage_id,
      artifact.artifact_type,
      artifact.name,
      artifact.category,
      JSON.stringify(artifact.data_payload || {}),
      artifact.raw_offset_range || null,
      artifact.extracted_at
    );
  }

  static getArtifactsByInvestigation(investigationId: string): ForensicArtifact[] {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM artifacts WHERE investigation_id = ? ORDER BY extracted_at DESC`);
    const rows = stmt.all(investigationId) as any[];
    return rows.map((r) => ({
      artifact_id: r.artifact_id,
      evidence_id: r.evidence_id,
      investigation_id: r.investigation_id,
      stage_id: r.stage_id,
      artifact_type: r.artifact_type,
      name: r.name,
      category: r.category,
      data_payload: JSON.parse(r.data_payload || '{}'),
      raw_offset_range: r.raw_offset_range,
      extracted_at: r.extracted_at,
    }));
  }

  // --- Timeline Events ---
  static createTimelineEvent(event: TimelineEvent): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO timeline_events (
        event_id, evidence_id, investigation_id, artifact_id,
        timestamp_utc, timestamp_raw, timestamp_precision, timezone_offset,
        event_type, source_parser, source_field, description, confidence
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      event.event_id,
      event.evidence_id,
      event.investigation_id,
      event.artifact_id || null,
      event.timestamp_utc,
      event.timestamp_raw,
      event.timestamp_precision,
      event.timezone_offset,
      event.event_type,
      event.source_parser,
      event.source_field,
      event.description,
      event.confidence
    );
  }

  static getTimelineByInvestigation(investigationId: string): TimelineEvent[] {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM timeline_events WHERE investigation_id = ? ORDER BY timestamp_utc ASC`);
    const rows = stmt.all(investigationId) as any[];
    return rows.map((r) => ({
      event_id: r.event_id,
      evidence_id: r.evidence_id,
      investigation_id: r.investigation_id,
      artifact_id: r.artifact_id,
      timestamp_utc: r.timestamp_utc,
      timestamp_raw: r.timestamp_raw,
      timestamp_precision: r.timestamp_precision,
      timezone_offset: r.timezone_offset,
      event_type: r.event_type,
      source_parser: r.source_parser,
      source_field: r.source_field,
      description: r.description,
      confidence: r.confidence,
    }));
  }

  // --- Findings ---
  static createFinding(finding: ForensicFinding): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO findings (
        finding_id, evidence_id, investigation_id, title,
        category, severity, description, technical_rationale,
        analysis_method, source_module, supporting_artifact_ids,
        limitations, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      finding.finding_id,
      finding.evidence_id,
      finding.investigation_id,
      finding.title,
      finding.category,
      finding.severity,
      finding.description,
      finding.technical_rationale,
      finding.analysis_method,
      finding.source_module,
      JSON.stringify(finding.supporting_artifact_ids || []),
      finding.limitations || null,
      finding.created_at
    );
  }

  static getFindingsByInvestigation(investigationId: string): ForensicFinding[] {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM findings WHERE investigation_id = ? ORDER BY created_at DESC`);
    const rows = stmt.all(investigationId) as any[];
    return rows.map((r) => ({
      finding_id: r.finding_id,
      evidence_id: r.evidence_id,
      investigation_id: r.investigation_id,
      title: r.title,
      category: r.category,
      severity: r.severity,
      description: r.description,
      technical_rationale: r.technical_rationale,
      analysis_method: r.analysis_method,
      source_module: r.source_module,
      supporting_artifact_ids: JSON.parse(r.supporting_artifact_ids || '[]'),
      limitations: r.limitations,
      created_at: r.created_at,
    }));
  }

  // --- Audit Logs ---
  static createAuditEvent(event: AuditEvent): void {
    const db = getDb();
    const stmt = db.prepare(`
      INSERT INTO audit_events (
        event_id, investigation_id, timestamp, actor_type,
        action, object_type, object_id, result, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      event.event_id,
      event.investigation_id,
      event.timestamp,
      event.actor_type,
      event.action,
      event.object_type,
      event.object_id,
      event.result,
      JSON.stringify(event.metadata || {})
    );
  }

  static getAuditLogsByInvestigation(investigationId: string): AuditEvent[] {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM audit_events WHERE investigation_id = ? ORDER BY timestamp DESC`);
    const rows = stmt.all(investigationId) as any[];
    return rows.map((r) => ({
      event_id: r.event_id,
      investigation_id: r.investigation_id,
      timestamp: r.timestamp,
      actor_type: r.actor_type,
      action: r.action,
      object_type: r.object_type,
      object_id: r.object_id,
      result: r.result,
      metadata: JSON.parse(r.metadata || '{}'),
    }));
  }

  // --- Reports ---
  static createReport(report: ForensicReport): void {
    const db = getDb();
    const expiresAt = report.expires_at || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const stmt = db.prepare(`
      INSERT INTO reports (
        report_id, investigation_id, report_sha256, verification_token,
        merkle_root, generated_at, expires_at, storage_path, file_size_bytes, report_manifest, session_purged
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      report.report_id,
      report.investigation_id,
      report.report_sha256,
      report.verification_token,
      report.merkle_root,
      report.generated_at,
      expiresAt,
      report.storage_path,
      report.file_size_bytes,
      JSON.stringify(report.report_manifest || {}),
      report.session_purged ? 1 : 0
    );
  }

  static getReportByInvestigation(investigationId: string): ForensicReport | null {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM reports WHERE investigation_id = ? ORDER BY generated_at DESC LIMIT 1`);
    const r = stmt.get(investigationId) as any;
    if (!r) return null;
    return {
      report_id: r.report_id,
      investigation_id: r.investigation_id,
      report_sha256: r.report_sha256,
      verification_token: r.verification_token,
      merkle_root: r.merkle_root,
      generated_at: r.generated_at,
      expires_at: r.expires_at || new Date(new Date(r.generated_at).getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      session_purged: Boolean(r.session_purged),
      storage_path: r.storage_path,
      file_size_bytes: Number(r.file_size_bytes),
      report_manifest: JSON.parse(r.report_manifest || '{}'),
    };
  }

  static getReportByVerificationToken(token: string): ForensicReport | null {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM reports WHERE verification_token = ?`);
    const r = stmt.get(token) as any;
    if (!r) return null;

    const expiresAt = r.expires_at || new Date(new Date(r.generated_at).getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
    // 7-day retention check: if expired, clean it up and return null
    if (new Date(expiresAt).getTime() < Date.now()) {
      this.deleteReport(r.report_id);
      return null;
    }

    return {
      report_id: r.report_id,
      investigation_id: r.investigation_id,
      report_sha256: r.report_sha256,
      verification_token: r.verification_token,
      merkle_root: r.merkle_root,
      generated_at: r.generated_at,
      expires_at: expiresAt,
      session_purged: Boolean(r.session_purged),
      storage_path: r.storage_path,
      file_size_bytes: Number(r.file_size_bytes),
      report_manifest: JSON.parse(r.report_manifest || '{}'),
    };
  }

  static deleteReport(reportId: string): void {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM reports WHERE report_id = ?`);
    const r = stmt.get(reportId) as any;
    if (r) {
      if (fs.existsSync(r.storage_path)) {
        try {
          fs.unlinkSync(r.storage_path);
        } catch {}
      }
      db.prepare(`DELETE FROM reports WHERE report_id = ?`).run(reportId);
    }
  }

  // --- Full Aggregate ---
  static getFullInvestigationDetails(investigationId: string): InvestigationFullDetails | null {
    const session = this.getInvestigation(investigationId);
    if (!session) return null;

    const evidence = this.getEvidenceByInvestigation(investigationId);
    const hashes: EvidenceHash[] = [];
    const jobs: ProcessingJob[] = [];
    const stages: ProcessingStage[] = [];

    for (const ev of evidence) {
      hashes.push(...this.getHashesByEvidence(ev.evidence_id));
      stages.push(...this.getStagesByEvidence(ev.evidence_id));
    }

    const artifacts = this.getArtifactsByInvestigation(investigationId);
    const timeline = this.getTimelineByInvestigation(investigationId);
    const findings = this.getFindingsByInvestigation(investigationId);
    const audit_logs = this.getAuditLogsByInvestigation(investigationId);
    const report = this.getReportByInvestigation(investigationId) || undefined;

    return {
      session,
      evidence,
      hashes,
      jobs,
      stages,
      artifacts,
      timeline,
      findings,
      audit_logs,
      report,
    };
  }

  // --- Deletion / Purge Lifecycle ---
  // When an anonymous session is purged, raw evidence and artifacts are wiped immediately.
  // The Report and its Verification Token PERSIST for 7 days so report authenticity remains provable!
  static deleteInvestigation(investigationId: string): void {
    const db = getDb();
    
    // Securely purge raw evidence vault and extracted artifacts
    const vaultPath = path.join(STORAGE_ROOT, 'evidence_vault', investigationId);
    const artPath = path.join(STORAGE_ROOT, 'artifacts_store', investigationId);

    for (const p of [vaultPath, artPath]) {
      if (fs.existsSync(p)) {
        fs.rmSync(p, { recursive: true, force: true });
      }
    }

    // Flag reports associated with this investigation as session_purged = 1 (proof persists for 7 days)
    db.prepare(`UPDATE reports SET session_purged = 1 WHERE investigation_id = ?`).run(investigationId);

    // Delete session and raw operational records from DB
    db.prepare(`DELETE FROM audit_events WHERE investigation_id = ?`).run(investigationId);
    db.prepare(`DELETE FROM findings WHERE investigation_id = ?`).run(investigationId);
    db.prepare(`DELETE FROM timeline_events WHERE investigation_id = ?`).run(investigationId);
    db.prepare(`DELETE FROM artifacts WHERE investigation_id = ?`).run(investigationId);
    db.prepare(`DELETE FROM processing_stages WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE investigation_id = ?)`).run(investigationId);
    db.prepare(`DELETE FROM processing_jobs WHERE investigation_id = ?`).run(investigationId);
    db.prepare(`DELETE FROM evidence_hashes WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE investigation_id = ?)`).run(investigationId);
    db.prepare(`DELETE FROM evidence WHERE investigation_id = ?`).run(investigationId);
    db.prepare(`DELETE FROM investigations WHERE investigation_id = ?`).run(investigationId);
  }

  // --- 7-Day / 24-Hour Retention Cleaner ---
  static cleanExpiredInvestigationsAndReports(): { purgedInvestigations: number; purgedReports: number } {
    const db = getDb();
    const now = new Date().toISOString();

    // 1. Purge expired investigation sessions (24h retention)
    const expiredInvStmt = db.prepare(`SELECT investigation_id FROM investigations WHERE expires_at < ?`);
    const expiredInvs = expiredInvStmt.all(now) as { investigation_id: string }[];
    for (const inv of expiredInvs) {
      this.deleteInvestigation(inv.investigation_id);
    }

    // 2. Purge expired reports (7-day retention)
    const expiredRptStmt = db.prepare(`SELECT report_id, storage_path FROM reports WHERE expires_at < ?`);
    const expiredRpts = expiredRptStmt.all(now) as { report_id: string; storage_path: string }[];
    for (const rpt of expiredRpts) {
      this.deleteReport(rpt.report_id);
    }

    return {
      purgedInvestigations: expiredInvs.length,
      purgedReports: expiredRpts.length,
    };
  }
}
