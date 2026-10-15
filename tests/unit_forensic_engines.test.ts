import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { FileIdentificationEngine } from '../src/lib/forensics/engines/file-id';
import { CryptographicHashingEngine } from '../src/lib/forensics/engines/hashing';
import { StringsExtractorEngine } from '../src/lib/forensics/engines/strings-extractor';
import { ArchiveForensicEngine } from '../src/lib/forensics/engines/archive';
import { FindingsCorrelatorEngine } from '../src/lib/forensics/engines/findings-correlator';
import { MerkleSealer } from '../src/lib/reporting/merkle-sealer';
import { ForensicExecutionContext } from '../src/lib/forensics/types';

async function runUnitTests() {
  console.log('=== RUNNING SILHOUETTE REAPER FORENSIC UNIT TESTS ===\n');

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string) {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}`);
      failed++;
    }
  }

  // 1. File Identification Engine Test
  {
    const engine = new FileIdentificationEngine();
    
    // PDF Sample
    const pdfBuf = Buffer.from('%PDF-1.7\n1 0 obj\n<< /Title (Test) >>\nendobj\n%%EOF');
    const ctxPdf: ForensicExecutionContext = {
      investigationId: 'INV-TEST-001',
      evidenceId: 'EVD-001',
      jobId: 'JOB-001',
      stageOrder: 1,
      originalFilename: 'document.pdf',
      declaredMime: 'application/pdf',
      fileBuffer: pdfBuf,
      fileSize: pdfBuf.length,
      storagePath: '/dummy/path',
      artifactsSoFar: [],
    };
    const resPdf = await engine.execute(ctxPdf);
    assert(resPdf.artifacts[0].data_payload.detected_mime === 'application/pdf', 'File ID: Correctly identifies PDF magic bytes');

    // Executable PE (MZ header)
    const exeBuf = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(100)]);
    const ctxExe: ForensicExecutionContext = {
      investigationId: 'INV-TEST-002',
      evidenceId: 'EVD-002',
      jobId: 'JOB-002',
      stageOrder: 1,
      originalFilename: 'invoice.pdf', // Spoofed extension!
      declaredMime: 'application/pdf',
      fileBuffer: exeBuf,
      fileSize: exeBuf.length,
      storagePath: '/dummy/path',
      artifactsSoFar: [],
    };
    const resExe = await engine.execute(ctxExe);
    assert(resExe.artifacts[0].data_payload.detected_extension === 'exe', 'File ID: Detects PE Executable header despite .pdf extension');
  }

  // 2. Cryptographic Hashing Engine Test
  {
    const engine = new CryptographicHashingEngine();
    const testData = Buffer.from('Forensic Bit-Stream Integrity Verification Test Payload 2026');
    const expectedSha256 = crypto.createHash('sha256').update(testData).digest('hex');
    const expectedSha1 = crypto.createHash('sha1').update(testData).digest('hex');
    const expectedMd5 = crypto.createHash('md5').update(testData).digest('hex');

    const ctx: ForensicExecutionContext = {
      investigationId: 'INV-TEST-003',
      evidenceId: 'EVD-003',
      jobId: 'JOB-003',
      stageOrder: 2,
      originalFilename: 'evidence.bin',
      declaredMime: 'application/octet-stream',
      fileBuffer: testData,
      fileSize: testData.length,
      storagePath: '/dummy/path',
      artifactsSoFar: [],
    };

    const res = await engine.execute(ctx);
    const hashes = res.artifacts[0].data_payload;
    assert(hashes.sha256 === expectedSha256, 'Hashing: SHA-256 match');
    assert(hashes.sha1 === expectedSha1, 'Hashing: SHA-1 match');
    assert(hashes.md5 === expectedMd5, 'Hashing: MD5 match');
  }

  // 3. Strings & IOC Extractor Test
  {
    const engine = new StringsExtractorEngine();
    const payload = Buffer.from(
      'Server error at 192.168.1.100 communicating with https://c2.evil-corp.net/payload.bin using powershell.exe -enc AAAA\nPath: C:\\Windows\\System32\\cmd.exe'
    );
    const ctx: ForensicExecutionContext = {
      investigationId: 'INV-TEST-004',
      evidenceId: 'EVD-004',
      jobId: 'JOB-004',
      stageOrder: 4,
      originalFilename: 'memory.raw',
      declaredMime: 'application/octet-stream',
      fileBuffer: payload,
      fileSize: payload.length,
      storagePath: '/dummy/path',
      artifactsSoFar: [],
    };

    const res = await engine.execute(ctx);
    const data = res.artifacts[0].data_payload;
    assert(data.ipv4_addresses.includes('192.168.1.100'), 'Strings: Extracted IPv4 indicator');
    assert(data.urls.some((u: string) => u.includes('c2.evil-corp.net')), 'Strings: Extracted URL indicator');
    assert(data.detected_execution_indicators.some((i: any) => i.label.includes('PowerShell')), 'Strings: Extracted PowerShell indicator');
  }

  // 4. Archive & Zip Slip Security Test
  {
    const engine = new ArchiveForensicEngine();
    // Construct a raw ZIP with a crafted Local File Header containing ../../etc/passwd
    const filename = '../../etc/passwd';
    const fnBytes = Buffer.from(filename, 'utf8');
    const lfh = Buffer.alloc(30 + fnBytes.length);
    lfh.writeUInt32LE(0x04034b50, 0); // PK\x03\x04
    lfh.writeUInt16LE(20, 4); // version
    lfh.writeUInt16LE(0, 6); // flags
    lfh.writeUInt16LE(0, 8); // compression
    lfh.writeUInt16LE(0, 10); // time
    lfh.writeUInt16LE(0, 12); // date
    lfh.writeUInt32LE(0, 14); // crc
    lfh.writeUInt32LE(10, 18); // comp size
    lfh.writeUInt32LE(10, 22); // uncomp size
    lfh.writeUInt16LE(fnBytes.length, 26); // fn length
    lfh.writeUInt16LE(0, 28); // extra length
    fnBytes.copy(lfh, 30);

    // End of central directory record
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);

    const zipBuf = Buffer.concat([lfh, Buffer.from('0123456789'), eocd]);

    const ctx: ForensicExecutionContext = {
      investigationId: 'INV-TEST-005',
      evidenceId: 'EVD-005',
      jobId: 'JOB-005',
      stageOrder: 3,
      originalFilename: 'archive.zip',
      declaredMime: 'application/zip',
      fileBuffer: zipBuf,
      fileSize: zipBuf.length,
      storagePath: '/dummy/path',
      artifactsSoFar: [],
    };

    const res = await engine.execute(ctx);
    const data = res.artifacts[0].data_payload;
    assert(data.zip_slip_detected === true, 'Archive Engine: Detected Zip Slip path traversal vulnerability');
  }

  // 5. Findings Correlation Test
  {
    const engine = new FindingsCorrelatorEngine();
    const fakeArtifacts: any[] = [
      {
        artifact_id: 'ART-001',
        artifact_type: 'FILE_IDENTIFICATION',
        category: 'IDENTIFICATION',
        data_payload: {
          original_extension: 'jpg',
          detected_extension: 'exe',
          detected_mime: 'application/x-dosexec',
          format_description: 'Windows Portable Executable (PE)',
          header_hex: '4D 5A 90 00',
          entropy: 7.8,
        },
      },
      {
        artifact_id: 'ART-002',
        artifact_type: 'CRYPTOGRAPHIC_HASHES',
        category: 'IDENTIFICATION',
        data_payload: {
          sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        },
      },
    ];

    const ctx: ForensicExecutionContext = {
      investigationId: 'INV-TEST-006',
      evidenceId: 'EVD-006',
      jobId: 'JOB-006',
      stageOrder: 5,
      originalFilename: 'photo.jpg',
      declaredMime: 'image/jpeg',
      fileBuffer: Buffer.alloc(100),
      fileSize: 100,
      storagePath: '/dummy/path',
      artifactsSoFar: fakeArtifacts,
    };

    const res = await engine.execute(ctx);
    assert(res.findings.some((f) => f.category === 'EXTENSION_SPOOF'), 'Correlator: Generated Extension Spoof finding');
    assert(res.findings.some((f) => f.category === 'INTEGRITY'), 'Correlator: Generated Baseline Integrity finding');
    assert(
      res.findings.every((f) => f.supporting_artifact_ids.length > 0),
      'Correlator: Guaranteed non-empty supporting artifact provenance links'
    );
  }

  // 6. Merkle Sealer Test
  {
    const artifacts: any[] = [
      { artifact_id: 'ART-1', artifact_type: 'ID', data_payload: { val: 1 } },
      { artifact_id: 'ART-2', artifact_type: 'HASH', data_payload: { val: 2 } },
    ];
    const findings: any[] = [
      { finding_id: 'FND-1', title: 'T1', supporting_artifact_ids: ['ART-1'], technical_rationale: 'R1' },
    ];

    const root1 = MerkleSealer.generateMerkleRoot(artifacts, findings);
    const root2 = MerkleSealer.generateMerkleRoot(artifacts, findings);
    assert(root1 === root2 && root1.length === 64, 'Merkle Sealer: Produces deterministic 256-bit root hash');
  }

  console.log(`\n=== UNIT TEST SUMMARY: ${passed} PASSED, ${failed} FAILED ===\n`);
  if (failed > 0) process.exit(1);
}

runUnitTests().catch((err) => {
  console.error('Test execution error:', err);
  process.exit(1);
});
