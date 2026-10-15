import { NextRequest, NextResponse } from 'next/server';
import { ForensicRepository } from '@/lib/db/database';
import { verifySessionSecret } from '@/lib/security/auth';

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

    const details = ForensicRepository.getFullInvestigationDetails(investigationId);

    return NextResponse.json({
      success: true,
      data: details,
    });
  } catch (error: any) {
    console.error('Failed to get investigation:', error);
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(
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

    ForensicRepository.deleteInvestigation(investigationId);

    return NextResponse.json({
      success: true,
      message: `Investigation ${investigationId} and all associated evidence, artifacts, and reports have been permanently and securely purged.`,
    });
  } catch (error: any) {
    console.error('Failed to delete investigation:', error);
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
