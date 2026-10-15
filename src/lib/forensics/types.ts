import {
  ForensicArtifact,
  TimelineEvent,
  ForensicFinding,
  ProcessingStage,
} from '@/types/forensics';

export interface ForensicExecutionContext {
  investigationId: string;
  evidenceId: string;
  jobId: string;
  stageOrder: number;
  originalFilename: string;
  declaredMime: string;
  fileBuffer: Buffer;
  fileSize: number;
  storagePath: string;
  detectedMime?: string;
  detectedExtension?: string;
  artifactsSoFar: ForensicArtifact[];
}

export interface EngineResult {
  stage: Omit<ProcessingStage, 'stage_id' | 'job_id' | 'evidence_id'>;
  artifacts: Omit<ForensicArtifact, 'artifact_id' | 'evidence_id' | 'investigation_id' | 'stage_id' | 'extracted_at'>[];
  timelineEvents: Omit<TimelineEvent, 'event_id' | 'evidence_id' | 'investigation_id' | 'artifact_id'>[];
  findings: Omit<ForensicFinding, 'finding_id' | 'evidence_id' | 'investigation_id' | 'created_at'>[];
  warnings: string[];
  limitations: string[];
}

export interface ForensicEngine {
  engineId: string;
  name: string;
  version: string;
  supports(context: ForensicExecutionContext): boolean;
  execute(context: ForensicExecutionContext): Promise<EngineResult>;
}
