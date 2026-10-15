import { NextRequest, NextResponse } from 'next/server';
import { ForensicRepository } from '@/lib/db/database';
import { verifySessionSecret } from '@/lib/security/auth';
import { ForensicPdfGenerator } from '@/lib/reporting/pdf-generator';

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

    const details = ForensicRepository.getFullInvestigationDetails(investigationId);
    if (!details) {
      return NextResponse.json({ success: false, error: 'Investigation details unavailable' }, { status: 404 });
    }

    if (details.evidence.length === 0) {
      return NextResponse.json({ success: false, error: 'Cannot generate report for investigation with zero evidence' }, { status: 400 });
    }

    // Generate sealed PDF report
    const report = await ForensicPdfGenerator.generateReport(details);

    return NextResponse.json({
      success: true,
      data: report,
      download_url: `/api/v1/investigations/${investigationId}/reports/${report.report_id}/download`,
      message: 'Cryptographically sealed forensic report generated successfully.',
    });
  } catch (error: any) {
    console.error('Report generation error:', error);
    return NextResponse.json({ success: false, error: 'Internal server error generating report' }, { status: 500 });
  }
}

export async function GET(
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

    const report = ForensicRepository.getReportByInvestigation(investigationId);
    if (!report) {
      return NextResponse.json({ success: false, error: 'Report not found' }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      data: report,
      download_url: `/api/v1/investigations/${investigationId}/reports/${report.report_id}/download`,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
