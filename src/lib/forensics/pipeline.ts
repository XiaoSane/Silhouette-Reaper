import fs from 'fs';
import { ForensicRepository } from '@/lib/db/database';
import { generateEntityId } from '@/lib/security/auth';
import { ForensicEngine, ForensicExecutionContext } from './types';
import { FileIdentificationEngine } from './engines/file-id';
import { CryptographicHashingEngine } from './engines/hashing';
import { ExifImageEngine } from './engines/exif-image';
import { PdfForensicEngine } from './engines/pdf-parser';
import { OfficeXmlEngine } from './engines/office-xml';
import { ArchiveForensicEngine } from './engines/archive';
import { LogForensicEngine } from './engines/log-parser';
import { StringsExtractorEngine } from './engines/strings-extractor';
import { FindingsCorrelatorEngine } from './engines/findings-correlator';
import { ForensicArtifact, TimelineEvent, ForensicFinding } from '@/types/forensics';

export class ForensicPipelineOrchestrator {
  private engines: ForensicEngine[] = [
    new FileIdentificationEngine(),
    new CryptographicHashingEngine(),
    new ExifImageEngine(),
    new PdfForensicEngine(),
    new OfficeXmlEngine(),
    new ArchiveForensicEngine(),
    new LogForensicEngine(),
    new StringsExtractorEngine(),
    new FindingsCorrelatorEngine(),
  ];

  async processEvidence(
    investigationId: string,
    evidenceId: string,
    onProgress?: (stageName: string, progressPercent: number) => void
  ): Promise<void> {
    const evidence = ForensicRepository.getEvidence(evidenceId);
    if (!evidence) {
      throw new Error(`Evidence ${evidenceId} not found`);
    }

    // Safeguard: Skip re-processing already completed evidence
    if (evidence.processing_status === 'COMPLETED') {
      return;
    }

    const jobId = generateEntityId('JOB');
    const now = new Date().toISOString();

    // Create Job
    ForensicRepository.createJob({
      job_id: jobId,
      evidence_id: evidenceId,
      investigation_id: investigationId,
      status: 'RUNNING',
      queued_at: now,
      started_at: now,
    });

    ForensicRepository.updateInvestigationStatus(investigationId, 'EXAMINATION');
    ForensicRepository.updateEvidenceProcessingStatus(evidenceId, 'PROCESSING');

    ForensicRepository.createAuditEvent({
      event_id: generateEntityId('AUD'),
      investigation_id: investigationId,
      timestamp: now,
      actor_type: 'SYSTEM_WORKER',
      action: 'EXAMINATION_STARTED',
      object_type: 'EVIDENCE',
      object_id: evidenceId,
      result: 'SUCCESS',
      metadata: { jobId, filename: evidence.original_filename },
    });

    try {
      // Read evidence in READ-ONLY mode
      if (!fs.existsSync(evidence.storage_path)) {
        throw new Error(`Evidence file missing from vault at ${evidence.storage_path}`);
      }

      const fileBuffer = fs.readFileSync(evidence.storage_path);

      const context: ForensicExecutionContext = {
        investigationId,
        evidenceId,
        jobId,
        stageOrder: 1,
        originalFilename: evidence.original_filename,
        declaredMime: evidence.declared_mime,
        fileBuffer,
        fileSize: fileBuffer.length,
        storagePath: evidence.storage_path,
        detectedMime: evidence.detected_mime,
        detectedExtension: evidence.detected_extension,
        artifactsSoFar: [],
      };

      const collectedArtifacts: ForensicArtifact[] = [];
      const collectedTimeline: TimelineEvent[] = [];
      const collectedFindings: ForensicFinding[] = [];

      let stageOrder = 1;
      const totalEngines = this.engines.length;

      for (let i = 0; i < totalEngines; i++) {
        const engine = this.engines[i];

        if (!engine.supports(context)) {
          continue;
        }

        context.stageOrder = stageOrder;
        const progressPercent = Math.round(((i + 1) / totalEngines) * 100);
        if (onProgress) {
          onProgress(engine.name, progressPercent);
        }

        const stageId = generateEntityId('STG');
        const stageStartTime = new Date().toISOString();

        try {
          const result = await engine.execute(context);

          // Save Stage
          ForensicRepository.createStage({
            stage_id: stageId,
            job_id: jobId,
            evidence_id: evidenceId,
            stage_name: result.stage.stage_name,
            stage_order: stageOrder++,
            tool_name: result.stage.tool_name,
            tool_version: result.stage.tool_version,
            status: result.stage.status,
            start_time: result.stage.start_time,
            end_time: result.stage.end_time,
            duration_ms: result.stage.duration_ms,
            execution_metadata: result.stage.execution_metadata,
            warnings: result.stage.warnings,
            errors: result.stage.errors,
          });

          const stageArtifacts: ForensicArtifact[] = [];

          // Save Artifacts
          for (const art of result.artifacts) {
            const artifactId = generateEntityId('ART');
            const fullArtifact: ForensicArtifact = {
              artifact_id: artifactId,
              evidence_id: evidenceId,
              investigation_id: investigationId,
              stage_id: stageId,
              artifact_type: art.artifact_type,
              name: art.name,
              category: art.category,
              data_payload: art.data_payload,
              raw_offset_range: art.raw_offset_range,
              extracted_at: new Date().toISOString(),
            };
            ForensicRepository.createArtifact(fullArtifact);
            collectedArtifacts.push(fullArtifact);
            stageArtifacts.push(fullArtifact);
            context.artifactsSoFar.push(fullArtifact);

            // Update detected mime / extension in context if file-id engine ran
            if (art.artifact_type === 'FILE_IDENTIFICATION') {
              context.detectedMime = art.data_payload.detected_mime;
              context.detectedExtension = art.data_payload.detected_extension;
            }
          }

          // Save Timeline Events
          for (const tle of result.timelineEvents) {
            const eventId = generateEntityId('TLE');
            const associatedArtifactId = stageArtifacts[0]?.artifact_id || collectedArtifacts[collectedArtifacts.length - 1]?.artifact_id;
            const fullTimeline: TimelineEvent = {
              event_id: eventId,
              evidence_id: evidenceId,
              investigation_id: investigationId,
              artifact_id: associatedArtifactId,
              timestamp_utc: tle.timestamp_utc,
              timestamp_raw: tle.timestamp_raw,
              timestamp_precision: tle.timestamp_precision,
              timezone_offset: tle.timezone_offset,
              event_type: tle.event_type,
              source_parser: tle.source_parser,
              source_field: tle.source_field,
              description: tle.description,
              confidence: tle.confidence,
            };
            ForensicRepository.createTimelineEvent(fullTimeline);
            collectedTimeline.push(fullTimeline);
          }

          // Save Findings
          for (const fnd of result.findings) {
            const findingId = generateEntityId('FND');
            const fullFinding: ForensicFinding = {
              finding_id: findingId,
              evidence_id: evidenceId,
              investigation_id: investigationId,
              title: fnd.title,
              category: fnd.category,
              severity: fnd.severity,
              description: fnd.description,
              technical_rationale: fnd.technical_rationale,
              analysis_method: fnd.analysis_method,
              source_module: fnd.source_module,
              supporting_artifact_ids: fnd.supporting_artifact_ids,
              limitations: fnd.limitations,
              created_at: new Date().toISOString(),
            };
            ForensicRepository.createFinding(fullFinding);
            collectedFindings.push(fullFinding);
          }
        } catch (stageErr: any) {
          ForensicRepository.createStage({
            stage_id: stageId,
            job_id: jobId,
            evidence_id: evidenceId,
            stage_name: engine.name,
            stage_order: stageOrder++,
            tool_name: engine.name,
            tool_version: engine.version,
            status: 'FAILED',
            start_time: stageStartTime,
            end_time: new Date().toISOString(),
            duration_ms: 0,
            execution_metadata: {},
            warnings: [],
            errors: [stageErr.message || 'Unknown stage execution exception'],
          });
        }
      }

      // Mark Job & Evidence completed
      const completionTime = new Date().toISOString();
      ForensicRepository.updateJobStatus(jobId, 'COMPLETED', completionTime);
      ForensicRepository.updateEvidenceProcessingStatus(evidenceId, 'COMPLETED');
      ForensicRepository.updateInvestigationStatus(investigationId, 'FINDINGS_READY');

      ForensicRepository.createAuditEvent({
        event_id: generateEntityId('AUD'),
        investigation_id: investigationId,
        timestamp: completionTime,
        actor_type: 'SYSTEM_WORKER',
        action: 'EXAMINATION_COMPLETED',
        object_type: 'EVIDENCE',
        object_id: evidenceId,
        result: 'SUCCESS',
        metadata: {
          jobId,
          artifacts_count: collectedArtifacts.length,
          timeline_count: collectedTimeline.length,
          findings_count: collectedFindings.length,
        },
      });
    } catch (err: any) {
      const failTime = new Date().toISOString();
      ForensicRepository.updateJobStatus(jobId, 'FAILED', failTime, err.message);
      ForensicRepository.updateEvidenceProcessingStatus(evidenceId, 'FAILED');
      ForensicRepository.updateInvestigationStatus(investigationId, 'FAILED');

      ForensicRepository.createAuditEvent({
        event_id: generateEntityId('AUD'),
        investigation_id: investigationId,
        timestamp: failTime,
        actor_type: 'SYSTEM_WORKER',
        action: 'EXAMINATION_FAILED',
        object_type: 'EVIDENCE',
        object_id: evidenceId,
        result: 'FAILURE',
        metadata: { error: err.message },
      });
      throw err;
    }
  }
}
