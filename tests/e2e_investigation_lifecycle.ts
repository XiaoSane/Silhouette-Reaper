import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ForensicRepository } from '../src/lib/db/database';
import {
  generateInvestigationId,
  generateSessionSecret,
  hashSessionSecret,
  generateEntityId,
} from '../src/lib/security/auth';
import { ForensicPipelineOrchestrator } from '../src/lib/forensics/pipeline';
import { ForensicPdfGenerator } from '../src/lib/reporting/pdf-generator';
import { EvidenceRecord } from '../src/types/forensics';

async function runE2ETest() {
  console.log('=== STARTING END-TO-END DIGITAL FORENSICS LIFECYCLE TEST ===\n');

  // STEP 1: INITIALIZE ANONYMOUS INVESTIGATION
  const investigationId = generateInvestigationId();
  const sessionSecret = generateSessionSecret();
  const sessionSecretHash = hashSessionSecret(sessionSecret);

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  ForensicRepository.createInvestigation({
    investigation_id: investigationId,
    session_secret_hash: sessionSecretHash,
    status: 'CREATED',
    evidence_count: 0,
    retention_hours: 24,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    last_activity_at: now.toISOString(),
  });

  console.log(`[1] Created Anonymous Investigation: ${investigationId}`);

  // Setup vault directory
  const vaultDir = path.join(process.cwd(), 'storage', 'evidence_vault', investigationId);
  fs.mkdirSync(vaultDir, { recursive: true });

  // STEP 2: INTAKE 3 EVIDENCE SAMPLES
  // Sample 1: Clean PDF Document
  const pdfContent = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Title (Confidential Financial Summary) /Author (Jane Doe) /Producer (Acrobat Distiller 11.0) /CreationDate (D:20260115083000Z) /ModDate (D:20260116142000Z) >>\nendobj\n%%EOF'
  );
  const ev1Id = generateEntityId('EVD');
  const ev1Path = path.join(vaultDir, `${ev1Id}_financial_summary.pdf`);
  fs.writeFileSync(ev1Path, pdfContent);

  const ev1: EvidenceRecord = {
    evidence_id: ev1Id,
    investigation_id: investigationId,
    original_filename: 'financial_summary.pdf',
    declared_mime: 'application/pdf',
    detected_mime: 'application/pdf',
    detected_extension: 'pdf',
    size_bytes: pdfContent.length,
    primary_sha256: crypto.createHash('sha256').update(pdfContent).digest('hex'),
    sha1: crypto.createHash('sha1').update(pdfContent).digest('hex'),
    md5: crypto.createHash('md5').update(pdfContent).digest('hex'),
    storage_path: ev1Path,
    preservation_status: 'PRESERVED_RO',
    processing_status: 'PENDING',
    acquisition_timestamp: new Date().toISOString(),
    upload_timestamp: new Date().toISOString(),
  };
  ForensicRepository.createEvidence(ev1);
  ForensicRepository.incrementEvidenceCount(investigationId);
  console.log(`[2A] Ingested Evidence 1: ${ev1.original_filename} (SHA-256: ${ev1.primary_sha256.slice(0, 16)}...)`);

  // Sample 2: Extension-Spoofed Malicious Executable disguised as .pdf
  const peHeader = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
  const maliciousStrings = Buffer.from(
    '\nC:\\Windows\\Temp\\stage.bin\npowershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==\nConnecting to http://185.220.101.5/c2/beacon\n'
  );
  const exeContent = Buffer.concat([peHeader, maliciousStrings, Buffer.alloc(500, 0xcc)]);
  const ev2Id = generateEntityId('EVD');
  const ev2Path = path.join(vaultDir, `${ev2Id}_invoice_scan.pdf`);
  fs.writeFileSync(ev2Path, exeContent);

  const ev2: EvidenceRecord = {
    evidence_id: ev2Id,
    investigation_id: investigationId,
    original_filename: 'invoice_scan.pdf', // Spoofed!
    declared_mime: 'application/pdf',
    detected_mime: 'application/pdf',
    detected_extension: 'pdf',
    size_bytes: exeContent.length,
    primary_sha256: crypto.createHash('sha256').update(exeContent).digest('hex'),
    sha1: crypto.createHash('sha1').update(exeContent).digest('hex'),
    md5: crypto.createHash('md5').update(exeContent).digest('hex'),
    storage_path: ev2Path,
    preservation_status: 'PRESERVED_RO',
    processing_status: 'PENDING',
    acquisition_timestamp: new Date().toISOString(),
    upload_timestamp: new Date().toISOString(),
  };
  ForensicRepository.createEvidence(ev2);
  ForensicRepository.incrementEvidenceCount(investigationId);
  console.log(`[2B] Ingested Evidence 2: ${ev2.original_filename} (Disguised PE Executable)`);

  // Sample 3: Web Server Reconnaissance Log
  const logContent = Buffer.from(
    '198.51.100.42 - - [17/Sep/2026:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 4520\n' +
    '198.51.100.42 - - [17/Sep/2026:10:15:32 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 162\n' +
    '198.51.100.42 - - [17/Sep/2026:10:15:35 +0000] "GET /api/users?id=1+union+select+null,password+from+admin HTTP/1.1" 500 240\n'
  );
  const ev3Id = generateEntityId('EVD');
  const ev3Path = path.join(vaultDir, `${ev3Id}_access_auth.log`);
  fs.writeFileSync(ev3Path, logContent);

  const ev3: EvidenceRecord = {
    evidence_id: ev3Id,
    investigation_id: investigationId,
    original_filename: 'access_auth.log',
    declared_mime: 'text/plain',
    detected_mime: 'text/plain',
    detected_extension: 'log',
    size_bytes: logContent.length,
    primary_sha256: crypto.createHash('sha256').update(logContent).digest('hex'),
    sha1: crypto.createHash('sha1').update(logContent).digest('hex'),
    md5: crypto.createHash('md5').update(logContent).digest('hex'),
    storage_path: ev3Path,
    preservation_status: 'PRESERVED_RO',
    processing_status: 'PENDING',
    acquisition_timestamp: new Date().toISOString(),
    upload_timestamp: new Date().toISOString(),
  };
  ForensicRepository.createEvidence(ev3);
  ForensicRepository.incrementEvidenceCount(investigationId);
  console.log(`[2C] Ingested Evidence 3: ${ev3.original_filename} (Web Access Log)`);

  // STEP 3: DISPATCH FORENSIC PROCESSING PIPELINE
  console.log('\n[3] Dispatching Forensic Pipeline across all evidence...');
  const orchestrator = new ForensicPipelineOrchestrator();

  await orchestrator.processEvidence(investigationId, ev1Id);
  console.log(`  -> Processed Evidence 1 (${ev1.original_filename})`);

  await orchestrator.processEvidence(investigationId, ev2Id);
  console.log(`  -> Processed Evidence 2 (${ev2.original_filename})`);

  await orchestrator.processEvidence(investigationId, ev3Id);
  console.log(`  -> Processed Evidence 3 (${ev3.original_filename})`);

  // STEP 4: VERIFY REPOSITORY ARTIFACTS, TIMELINE, AND FINDINGS
  const fullDetails = ForensicRepository.getFullInvestigationDetails(investigationId);
  if (!fullDetails) throw new Error('Investigation details not found in repository');

  console.log(`\n[4] Examination Extraction Metrics:`);
  console.log(`  • Extracted Artifacts: ${fullDetails.artifacts.length}`);
  console.log(`  • Normalized Timeline Events: ${fullDetails.timeline.length}`);
  console.log(`  • Correlated Forensic Findings: ${fullDetails.findings.length}`);
  console.log(`  • Recorded Custody Audit Events: ${fullDetails.audit_logs.length}`);

  // Validation Checks
  if (fullDetails.artifacts.length === 0) throw new Error('Zero artifacts extracted');
  if (fullDetails.timeline.length === 0) throw new Error('Zero timeline events generated');
  if (fullDetails.findings.length === 0) throw new Error('Zero findings generated');

  // Verify Extension Spoof Finding exists for Evidence 2
  const spoofFinding = fullDetails.findings.find((f) => f.category === 'EXTENSION_SPOOF');
  if (!spoofFinding) {
    throw new Error('Expected extension spoof finding for invoice_scan.pdf not generated');
  }
  console.log(`  ✓ Extension Spoofing Confirmed: "${spoofFinding.title}" [Severity: ${spoofFinding.severity}]`);

  // Verify Web Attack Finding exists for Evidence 3
  const attackFinding = fullDetails.findings.find((f) => f.category === 'SECURITY_EVENT' && f.title.includes('Web Attack'));
  if (!attackFinding) {
    throw new Error('Expected web attack finding for access_auth.log not generated');
  }
  console.log(`  ✓ Security Threat Observation Confirmed: "${attackFinding.title}"`);

  // STEP 5: COMPILE CRYPTOGRAPHICALLY SEALED FORENSIC REPORT
  console.log('\n[5] Compiling Deterministic Forensic Examination Report...');
  const report = await ForensicPdfGenerator.generateReport(fullDetails);

  console.log(`  ✓ PDF Compiled Successfully: ${report.storage_path}`);
  console.log(`  • Report File Size: ${(report.file_size_bytes / 1024).toFixed(2)} KB`);
  console.log(`  • Document SHA-256 Digest: ${report.report_sha256}`);
  console.log(`  • Merkle Tree Root: ${report.merkle_root}`);
  console.log(`  • Verification Token: ${report.verification_token}`);

  // Verify PDF file exists and is valid
  if (!fs.existsSync(report.storage_path)) throw new Error('Generated PDF report file does not exist on disk');
  const pdfHeader = fs.readFileSync(report.storage_path, { encoding: 'utf8', flag: 'r' }).slice(0, 5);
  if (pdfHeader !== '%PDF-') throw new Error('Generated report file is not a valid PDF document');

  // STEP 6: VERIFY REPORT VIA TOKEN IN REPOSITORY
  console.log('\n[6] Validating Report Token Resolution...');
  const verifiedReport = ForensicRepository.getReportByVerificationToken(report.verification_token);
  if (!verifiedReport || verifiedReport.report_sha256 !== report.report_sha256) {
    throw new Error('Verification token lookup failed or hash mismatch');
  }
  console.log(`  ✓ Report Verified via Token: Status = AUTHENTIC_AND_VERIFIED`);

  // STEP 7: CLEANUP & RETENTION PURGE (7-DAY PROOF RETENTION TEST)
  console.log('\n[7] Testing Secure Zero-Fill & 7-Day Proof Preservation Lifecycle...');
  
  // Verify 7-day expires_at calculation
  const expiresAtDate = new Date(report.expires_at);
  const currentTime = new Date();
  const diffDays = Math.round((expiresAtDate.getTime() - currentTime.getTime()) / (1000 * 60 * 60 * 24));
  if (diffDays !== 7) {
    throw new Error(`Expected report expiration to be 7 days from creation, got ${diffDays} days`);
  }
  console.log(`  ✓ 7-Day Expiration Verified: Expires at ${report.expires_at} (~${diffDays} days)`);

  // Purge the anonymous investigation session
  ForensicRepository.deleteInvestigation(investigationId);
  const deletedSession = ForensicRepository.getInvestigation(investigationId);
  if (deletedSession !== null) throw new Error('Investigation session was not purged from DB');
  if (fs.existsSync(vaultDir)) throw new Error('Raw evidence vault directory was not removed from disk');
  console.log(`  ✓ Anonymous session ${investigationId} and raw vault files zero-filled & purged.`);

  // CRITICAL REQUIREMENT: Prove report verification token STILL resolves after session purge!
  const postPurgeVerified = ForensicRepository.getReportByVerificationToken(report.verification_token);
  if (!postPurgeVerified) {
    throw new Error('Verification token was lost when session was purged! Token must persist for 7 days.');
  }
  if (postPurgeVerified.report_sha256 !== report.report_sha256) {
    throw new Error('Verification SHA-256 mismatch after session purge');
  }
  if (!postPurgeVerified.session_purged) {
    throw new Error('Expected session_purged flag to be true on post-purge report verification');
  }
  console.log(`  ✓ Report validity proven post-purge! Token ${report.verification_token} remains active in 7-day public ledger.`);

  // Clean up test report artifact
  ForensicRepository.deleteReport(report.report_id);
  console.log(`  ✓ Test report cleaned up.`);

  console.log('\n===============================================================');
  console.log('🎉 COMPLETE END-TO-END DIGITAL FORENSICS LIFECYCLE TEST PASSED');
  console.log('===============================================================\n');
}

runE2ETest().catch((err) => {
  console.error('\n❌ E2E TEST FAILED:', err);
  process.exit(1);
});
