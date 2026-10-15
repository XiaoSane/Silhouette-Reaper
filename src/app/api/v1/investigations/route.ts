import { NextRequest, NextResponse } from 'next/server';
import { ForensicRepository } from '@/lib/db/database';
import {
  generateInvestigationId,
  generateSessionSecret,
  hashSessionSecret,
  generateEntityId,
} from '@/lib/security/auth';
import { InvestigationSession } from '@/types/forensics';

export async function POST(req: NextRequest) {
  try {
    const investigationId = generateInvestigationId();
    const sessionSecret = generateSessionSecret();
    const sessionSecretHash = hashSessionSecret(sessionSecret);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24-hour default retention

    const session: InvestigationSession = {
      investigation_id: investigationId,
      session_secret_hash: sessionSecretHash,
      status: 'CREATED',
      evidence_count: 0,
      retention_hours: 24,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      last_activity_at: now.toISOString(),
    };

    ForensicRepository.createInvestigation(session);

    ForensicRepository.createAuditEvent({
      event_id: generateEntityId('AUD'),
      investigation_id: investigationId,
      timestamp: now.toISOString(),
      actor_type: 'ANONYMOUS_SESSION',
      action: 'INVESTIGATION_CREATED',
      object_type: 'INVESTIGATION',
      object_id: investigationId,
      result: 'SUCCESS',
      metadata: { retention_hours: 24 },
    });

    return NextResponse.json({
      success: true,
      investigation_id: investigationId,
      session_secret: sessionSecret,
      created_at: session.created_at,
      expires_at: session.expires_at,
      status: session.status,
      message: 'Anonymous investigation session initialized. Securely store your session secret.',
    });
  } catch (error: any) {
    console.error('Failed to create investigation:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error initializing investigation session' },
      { status: 500 }
    );
  }
}
