import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import { ForensicRepository } from '@/lib/db/database';
import { verifySessionSecret } from '@/lib/security/auth';

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string; reportId: string } }
) {
  try {
    const { id: investigationId, reportId } = params;
    const sessionSecret = req.headers.get('x-session-secret') || req.nextUrl.searchParams.get('secret');

    const session = ForensicRepository.getInvestigation(investigationId);
    if (!session) {
      return NextResponse.json({ success: false, error: 'Investigation not found' }, { status: 404 });
    }

    if (!sessionSecret || !verifySessionSecret(sessionSecret, session.session_secret_hash)) {
      return NextResponse.json({ success: false, error: 'Unauthorized: Valid session secret required' }, { status: 401 });
    }

    const report = ForensicRepository.getReportByInvestigation(investigationId);
    if (!report || report.report_id !== reportId) {
      return NextResponse.json({ success: false, error: 'Report not found' }, { status: 404 });
    }

    if (!fs.existsSync(report.storage_path)) {
      return NextResponse.json({ success: false, error: 'Report file missing from disk' }, { status: 404 });
    }

    const fileBuffer = fs.readFileSync(report.storage_path);

    return new NextResponse(fileBuffer, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="Forensic_Report_${investigationId}_${reportId}.pdf"`,
        'Content-Length': fileBuffer.length.toString(),
        'X-Report-SHA256': report.report_sha256,
        'X-Verification-Token': report.verification_token,
      },
    });
  } catch (error: any) {
    console.error('Download error:', error);
    return NextResponse.json({ success: false, error: 'Internal server error downloading report' }, { status: 500 });
  }
}
