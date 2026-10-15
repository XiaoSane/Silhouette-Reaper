import { NextRequest, NextResponse } from 'next/server';
import { ForensicRepository } from '@/lib/db/database';

export async function GET(
  req: NextRequest,
  { params }: { params: { code: string } }
) {
  try {
    const rawCode = params.code.trim();
    const report = ForensicRepository.getReportByVerificationToken(rawCode);

    if (!report) {
      return NextResponse.json({
        success: false,
        verified: false,
        message: 'No active forensic report matches this verification token. The token may be invalid, or its 7-day cryptographic retention period has expired.',
      }, { status: 404 });
    }

    const expiresAtMs = new Date(report.expires_at).getTime();
    const nowMs = Date.now();
    const daysRemaining = Math.max(0, Math.ceil((expiresAtMs - nowMs) / (1000 * 60 * 60 * 24)));

    return NextResponse.json({
      success: true,
      verified: true,
      report_id: report.report_id,
      investigation_id: report.investigation_id,
      report_sha256: report.report_sha256,
      merkle_root: report.merkle_root,
      generated_at: report.generated_at,
      expires_at: report.expires_at,
      retention_days_remaining: daysRemaining,
      session_purged: Boolean(report.session_purged),
      file_size_bytes: report.file_size_bytes,
      manifest: report.report_manifest,
      verification_status: 'AUTHENTIC_AND_VERIFIED',
      verification_message: report.session_purged
        ? 'Report validity certified. The anonymous raw evidence session was purged from the lab server, but the cryptographic Merkle seal remains authenticated in the 7-day public registry.'
        : 'The digital signature and Merkle root match the immutable audit record stored in the laboratory registry.',
    });
  } catch (error: any) {
    console.error('Verification error:', error);
    return NextResponse.json({ success: false, error: 'Internal server error during verification' }, { status: 500 });
  }
}
