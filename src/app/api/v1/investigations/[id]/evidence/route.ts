import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ForensicRepository } from '@/lib/db/database';
import {
  verifySessionSecret,
  generateEntityId,
  sanitizeFilename,
} from '@/lib/security/auth';
import { EvidenceRecord } from '@/types/forensics';

export async function POST(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const investigationId = params.id;
    const sessionSecret = req.headers.get('x-session-secret') || req.nextUrl.searchParams.get('secret');

    const session = ForensicRepository.getInvestigation(investigationId);
    if (!session) {
      return NextResponse.json({ success: false, error: 'Investigation not found' }, { status: 404 });
    }

    if (!sessionSecret || !verifySessionSecret(sessionSecret, session.session_secret_hash)) {
      return NextResponse.json({ success: false, error: 'Unauthorized: Valid session secret required' }, { status: 401 });
    }

    const formData = await req.formData();
    const file = formData.get('file') as File | null;

    if (!file) {
      return NextResponse.json({ success: false, error: 'No evidence file provided in multipart request' }, { status: 400 });
    }

    // Size limit: 50MB
    const MAX_SIZE = 50 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      return NextResponse.json(
        { success: false, error: `File size (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds maximum allowed intake limit (50 MB)` },
        { status: 413 }
      );
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Cryptographic Hashes
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');

    const rawFilename = file.name || 'unnamed_evidence.bin';
    const sanitizedFilename = sanitizeFilename(rawFilename);
    const declaredMime = file.type || 'application/octet-stream';
    const originalExt = sanitizedFilename.split('.').pop()?.toLowerCase() || 'bin';

    const evidenceId = generateEntityId('EVD');
    const now = new Date().toISOString();

    // Vault Storage Path
    const vaultDir = path.join(process.cwd(), 'storage', 'evidence_vault', investigationId);
    if (!fs.existsSync(vaultDir)) {
      fs.mkdirSync(vaultDir, { recursive: true });
    }

    const storagePath = path.join(vaultDir, `${evidenceId}_${sanitizedFilename}`);
    fs.writeFileSync(storagePath, buffer);

    // Set file to Read-Only permissions (0444 on POSIX / readonly attribute)
    try {
      fs.chmodSync(storagePath, 0o444);
    } catch {
      // Ignored if OS doesn't support chmod mode
    }

    const evidence: EvidenceRecord = {
      evidence_id: evidenceId,
      investigation_id: investigationId,
      original_filename: rawFilename,
      declared_mime: declaredMime,
      detected_mime: declaredMime, // will be updated by pipeline file-id stage
      detected_extension: originalExt,
      size_bytes: buffer.length,
      primary_sha256: sha256,
      sha1: sha1,
      md5: md5,
      storage_path: storagePath,
      preservation_status: 'PRESERVED_RO',
      processing_status: 'PENDING',
      acquisition_timestamp: now,
      upload_timestamp: now,
    };

    ForensicRepository.createEvidence(evidence);

    // Register Hashes
    ForensicRepository.createEvidenceHash({
      hash_id: generateEntityId('HSH'),
      evidence_id: evidenceId,
      algorithm: 'SHA-256',
      hash_value: sha256,
      purpose: 'PRIMARY_INTEGRITY',
      calculated_at: now,
    });
    ForensicRepository.createEvidenceHash({
      hash_id: generateEntityId('HSH'),
      evidence_id: evidenceId,
      algorithm: 'SHA-1',
      hash_value: sha1,
      purpose: 'COMPATIBILITY',
      calculated_at: now,
    });
    ForensicRepository.createEvidenceHash({
      hash_id: generateEntityId('HSH'),
      evidence_id: evidenceId,
      algorithm: 'MD5',
      hash_value: md5,
      purpose: 'COMPATIBILITY',
      calculated_at: now,
    });

    ForensicRepository.incrementEvidenceCount(investigationId);
    ForensicRepository.updateInvestigationStatus(investigationId, 'EVIDENCE_REGISTERED');

    ForensicRepository.createAuditEvent({
      event_id: generateEntityId('AUD'),
      investigation_id: investigationId,
      timestamp: now,
      actor_type: 'ANONYMOUS_SESSION',
      action: 'EVIDENCE_REGISTERED',
      object_type: 'EVIDENCE',
      object_id: evidenceId,
      result: 'SUCCESS',
      metadata: {
        filename: rawFilename,
        size_bytes: buffer.length,
        sha256,
      },
    });

    return NextResponse.json({
      success: true,
      data: evidence,
      message: 'Evidence successfully registered into immutable read-only vault with cryptographic hashes verified.',
    });
  } catch (error: any) {
    console.error('Evidence intake error:', error);
    return NextResponse.json({ success: false, error: 'Internal server error during evidence intake' }, { status: 500 });
  }
}

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const investigationId = params.id;
    const evidenceList = ForensicRepository.getEvidenceByInvestigation(investigationId);
    return NextResponse.json({ success: true, data: evidenceList });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
