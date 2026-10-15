import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';
import { ForensicFinding } from '@/types/forensics';

export class FindingsCorrelatorEngine implements ForensicEngine {
  engineId = 'engine-findings-correlator';
  name = 'Forensic Finding Normalizer & Correlation Engine';
  version = '2.5.0';

  supports(_context: ForensicExecutionContext): boolean {
    return true; // Runs at the end of the pipeline
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const warnings: string[] = [];
    const limitations: string[] = [];
    const findings: EngineResult['findings'] = [];

    const artifacts = context.artifactsSoFar;

    // Find specific artifacts by type
    const fileIdArt = artifacts.find((a) => a.artifact_type === 'FILE_IDENTIFICATION');
    const hashArt = artifacts.find((a) => a.artifact_type === 'CRYPTOGRAPHIC_HASHES');
    const exifArt = artifacts.find((a) => a.artifact_type === 'IMAGE_EXIF_METADATA');
    const pdfArt = artifacts.find((a) => a.artifact_type === 'PDF_DOCUMENT_METADATA');
    const officeArt = artifacts.find((a) => a.artifact_type === 'OFFICE_DOCUMENT_METADATA');
    const archiveArt = artifacts.find((a) => a.artifact_type === 'ARCHIVE_STRUCTURE_MANIFEST');
    const stringsArt = artifacts.find((a) => a.artifact_type === 'EXTRACTED_INDICATORS');
    const logArt = artifacts.find((a) => a.artifact_type === 'LOG_PARSER_SUMMARY');

    // Rule 1: Integrity Baseline Finding
    if (hashArt) {
      findings.push({
        title: 'Cryptographic Bit-Stream Integrity Established',
        category: 'INTEGRITY',
        severity: 'INFORMATIONAL',
        description: `Authoritative SHA-256 digest calculated (${hashArt.data_payload.sha256}). Evidence preserved bit-for-bit in read-only immutable storage.`,
        technical_rationale: 'Cryptographic verification ensures baseline bit-stream authenticity before forensic parsing stages were executed.',
        analysis_method: 'SHA-256 (FIPS 180-4) Streaming Digest Calculation',
        source_module: this.name,
        supporting_artifact_ids: [hashArt.artifact_id],
        limitations: 'Proves file state at time of acquisition; does not establish external source provenance prior to intake.',
      });
    }

    // Rule 2: Extension Spoofing Check
    if (fileIdArt) {
      const origExt = fileIdArt.data_payload.original_extension || '';
      const detectedExt = fileIdArt.data_payload.detected_extension || '';
      const detectedMime = fileIdArt.data_payload.detected_mime || '';

      const dangerousExtensions = ['exe', 'dll', 'elf', 'scr', 'vbs', 'ps1', 'bat', 'zip'];
      const isDangerousType = dangerousExtensions.includes(detectedExt);
      const isDocumentClaim = ['jpg', 'jpeg', 'png', 'pdf', 'txt', 'docx', 'xlsx'].includes(origExt);

      if (origExt && detectedExt && origExt !== detectedExt) {
        if (isDangerousType && isDocumentClaim) {
          findings.push({
            title: `Severe Extension Mismatch / Possible Disguised Payload (.${origExt} vs .${detectedExt})`,
            category: 'EXTENSION_SPOOF',
            severity: 'HIGH',
            description: `Evidence was submitted with filename extension '.${origExt}', but magic byte inspection definitively identified the binary as ${fileIdArt.data_payload.format_description} (MIME: ${detectedMime}).`,
            technical_rationale: `Header magic bytes (${fileIdArt.data_payload.header_hex}) diverge from the declared extension '.${origExt}', commonly observed in social engineering or payload delivery vectors.`,
            analysis_method: 'Header Magic Byte Signature & MIME Verification',
            source_module: this.name,
            supporting_artifact_ids: [fileIdArt.artifact_id],
            limitations: 'Technical discrepancy verified; intention (malicious vs misconfigured export) requires contextual corroboration.',
          });
        } else {
          findings.push({
            title: `Minor Extension Mismatch (.${origExt} vs .${detectedExt})`,
            category: 'FILE_ANOMALY',
            severity: 'LOW',
            description: `Declared file extension '.${origExt}' differs from detected format signature '.${detectedExt}'.`,
            technical_rationale: `Container signature matches ${fileIdArt.data_payload.format_description}.`,
            analysis_method: 'Magic Byte Verification',
            source_module: this.name,
            supporting_artifact_ids: [fileIdArt.artifact_id],
          });
        }
      }

      // Rule 3: High Entropy
      if (fileIdArt.data_payload.entropy > 7.6 && !['zip', 'gz', 'docx', 'xlsx', 'jpg', 'png'].includes(detectedExt)) {
        findings.push({
          title: `High Shannon Entropy Score (${fileIdArt.data_payload.entropy} / 8.00)`,
          category: 'FILE_ANOMALY',
          severity: 'LOW',
          description: `Byte distribution across the file exhibits high entropy (${fileIdArt.data_payload.entropy}), consistent with encrypted blocks, packed code, or randomized data.`,
          technical_rationale: 'Uncompressed binary sections with entropy > 7.5 often indicate cryptographic payloads or binary packing.',
          analysis_method: 'Shannon Entropy Calculation',
          source_module: this.name,
          supporting_artifact_ids: [fileIdArt.artifact_id],
        });
      }
    }

    // Rule 4: Active Content / JavaScript in PDF
    if (pdfArt && pdfArt.data_payload.active_content) {
      const ac = pdfArt.data_payload.active_content;
      if (ac.has_javascript || ac.has_launch_action || ac.has_open_action) {
        findings.push({
          title: 'Active Scripting / Automatic Action Detected in PDF Document',
          category: 'EMBEDDED_OBJECT',
          severity: 'MEDIUM',
          description: `PDF structure contains active directives: ${[
            ac.has_javascript ? 'JavaScript Streams (/JS)' : '',
            ac.has_launch_action ? 'Launch Actions (/Launch)' : '',
            ac.has_open_action ? 'Automatic Open Action (/OpenAction)' : '',
          ]
            .filter(Boolean)
            .join(', ')}.`,
          technical_rationale: 'Automated execution triggers in PDF catalogs can execute scripts or spawn external processes upon document rendering in vulnerable viewers.',
          analysis_method: 'PDF Dictionary & Action Object Tokenization',
          source_module: this.name,
          supporting_artifact_ids: [pdfArt.artifact_id],
          limitations: 'Static detection of action dictionary; runtime execution behavior depends on client PDF reader security configurations.',
        });
      }
    }

    // Rule 5: Macros in Standard Office Document
    if (officeArt && officeArt.data_payload.has_vba_macros) {
      findings.push({
        title: 'Embedded VBA Macro Project in Office Container',
        category: 'EMBEDDED_OBJECT',
        severity: 'MEDIUM',
        description: 'VBA macro binary storage stream (vbaProject.bin) detected inside the OpenXML package structure.',
        technical_rationale: 'VBA code streams can automate document procedures and execute system macros.',
        analysis_method: 'OPC ZIP Package Directory Traversal',
        source_module: this.name,
        supporting_artifact_ids: [officeArt.artifact_id],
      });
    }

    // Rule 6: Archive Path Traversal / Zip Slip & Decompression Bomb
    if (archiveArt && archiveArt.data_payload.zip_slip_detected) {
      findings.push({
        title: 'Zip Slip Path Traversal Sequences in Archive Entries',
        category: 'SECURITY_EVENT',
        severity: 'HIGH',
        description: `Archive contains entries with relative path traversal patterns (e.g. '../'): ${archiveArt.data_payload.traversal_violating_entries.join(
          ', '
        )}.`,
        technical_rationale: 'Zip Slip is an extraction vulnerability allowing arbitrary file overwrite outside the destination directory if extracted without sanitization.',
        analysis_method: 'Archive Header Path Normalization',
        source_module: this.name,
        supporting_artifact_ids: [archiveArt.artifact_id],
      });
    }

    if (archiveArt && archiveArt.data_payload.is_decompression_bomb_risk) {
      findings.push({
        title: `Excessive Archive Decompression Ratio (${archiveArt.data_payload.compression_ratio}:1)`,
        category: 'SECURITY_EVENT',
        severity: 'HIGH',
        description: `Archive exhibits dangerous compression characteristics (ratio ${archiveArt.data_payload.compression_ratio}:1, total uncompressed ${(archiveArt.data_payload.total_uncompressed_bytes / (1024 * 1024)).toFixed(2)} MB), presenting a high decompression bomb (zip bomb) denial-of-service risk.`,
        technical_rationale: 'Anomalous compression expansion ratios exceeding 100:1 or uncompressed sizes > 250MB violate safe sandbox thresholds.',
        analysis_method: 'Archive Header Ratio & Size Expansion Analysis',
        source_module: this.name,
        supporting_artifact_ids: [archiveArt.artifact_id],
      });
    }

    // Rule 7: Execution Indicators in Strings
    if (stringsArt && stringsArt.data_payload.detected_execution_indicators?.length > 0) {
      const inds = stringsArt.data_payload.detected_execution_indicators;
      findings.push({
        title: `Suspicious System Command / Script Tokens Detected (${inds.length} indicators)`,
        category: 'SUSPICIOUS_STRING',
        severity: 'MEDIUM',
        description: `Static string analysis extracted suspicious execution commands: ${inds
          .map((i: any) => `${i.label} ("${i.matched_string}")`)
          .slice(0, 4)
          .join('; ')}.`,
        technical_rationale: 'Extracted command-line strings match known script execution and staging artifacts.',
        analysis_method: 'Regex IOC Pattern Matching over Printable ASCII/Unicode Streams',
        source_module: this.name,
        supporting_artifact_ids: [stringsArt.artifact_id],
        limitations: 'Strings present in binary or log stream do not conclusively prove execution occurred without secondary process/audit telemetry.',
      });
    }

    // Rule 8: Suspicious Web Requests in Logs
    if (logArt && logArt.data_payload.suspicious_requests_detected?.length > 0) {
      findings.push({
        title: `Suspicious Web Attack Requests in Log Stream (${logArt.data_payload.suspicious_requests_detected.length} occurrences)`,
        category: 'SECURITY_EVENT',
        severity: 'HIGH',
        description: `Web log stream contains directory traversal or SQL injection probe patterns: ${logArt.data_payload.suspicious_requests_detected
          .slice(0, 3)
          .join('; ')}.`,
        technical_rationale: 'HTTP access log entries exhibit patterns indicative of web reconnaissance or exploitation attempts.',
        analysis_method: 'HTTP Request Parameter & URI Inspection',
        source_module: this.name,
        supporting_artifact_ids: [logArt.artifact_id],
      });
    }

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'FINDINGS_CORRELATION',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          findings_generated: findings.length,
        },
        warnings,
        errors: [],
      },
      artifacts: [],
      timelineEvents: [],
      findings,
      warnings,
      limitations,
    };
  }
}
