import { NextRequest, NextResponse } from 'next/server';
import { ForensicRepository } from '@/lib/db/database';
import { verifySessionSecret } from '@/lib/security/auth';
import { ForensicPipelineOrchestrator } from '@/lib/forensics/pipeline';

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

    const evidenceList = ForensicRepository.getEvidenceByInvestigation(investigationId);
    if (evidenceList.length === 0) {
      return NextResponse.json({ success: false, error: 'No evidence registered in this investigation' }, { status: 400 });
    }

    // Filter to ONLY pending or failed evidence items
    const pendingEvidence = evidenceList.filter(
      (ev) => ev.processing_status === 'PENDING' || ev.processing_status === 'FAILED'
    );

    if (pendingEvidence.length === 0) {
      return NextResponse.json({
        success: true,
        data: ForensicRepository.getFullInvestigationDetails(investigationId),
        message: 'All registered evidence items have already been examined.',
        processed_count: 0,
      });
    }

    const orchestrator = new ForensicPipelineOrchestrator();

    // Process only pending or failed evidence
    const results = [];
    for (const ev of pendingEvidence) {
      try {
        await orchestrator.processEvidence(investigationId, ev.evidence_id);
        results.push({ evidence_id: ev.evidence_id, status: 'SUCCESS' });
      } catch (err: any) {
        results.push({ evidence_id: ev.evidence_id, status: 'FAILED', error: err.message });
      }
    }

    const updatedDetails = ForensicRepository.getFullInvestigationDetails(investigationId);

    return NextResponse.json({
      success: true,
      data: updatedDetails,
      message: `Forensic examination completed for ${results.filter((r) => r.status === 'SUCCESS').length} pending evidence item(s).`,
      processed_count: results.filter((r) => r.status === 'SUCCESS').length,
    });
  } catch (error: any) {
    console.error('Forensic pipeline error:', error);
    return NextResponse.json({ success: false, error: 'Internal server error during forensic examination' }, { status: 500 });
  }
}
