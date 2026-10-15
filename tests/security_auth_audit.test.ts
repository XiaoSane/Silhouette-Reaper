import assert from 'assert';
import { ForensicRepository } from '../src/lib/db/database';
import {
  generateInvestigationId,
  generateSessionSecret,
  hashSessionSecret,
  verifySessionSecret,
} from '../src/lib/security/auth';
import { GET as getInvestigation, DELETE as deleteInvestigation } from '../src/app/api/v1/investigations/[id]/route';
import { POST as postEvidence } from '../src/app/api/v1/investigations/[id]/evidence/route';
import { POST as postProcess } from '../src/app/api/v1/investigations/[id]/process/route';
import { POST as postReport, GET as getReport } from '../src/app/api/v1/investigations/[id]/reports/route';
import { GET as getDownload } from '../src/app/api/v1/investigations/[id]/reports/[reportId]/download/route';
import { NextRequest } from 'next/server';

async function runSecurityAuditTests() {
  console.log('=== RUNNING SECURITY & AUTHORIZATION REGRESSION TESTS ===\n');

  const invId = generateInvestigationId();
  const secret = generateSessionSecret();
  const secretHash = hashSessionSecret(secret);

  ForensicRepository.createInvestigation({
    investigation_id: invId,
    session_secret_hash: secretHash,
    status: 'CREATED',
    evidence_count: 0,
    retention_hours: 24,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    last_activity_at: new Date().toISOString(),
  });

  const baseUrl = `http://localhost:3000/api/v1/investigations/${invId}`;

  // Helper to construct NextRequest
  const makeReq = (url: string, method: string, headers: Record<string, string> = {}) => {
    return new NextRequest(url, { method, headers });
  };

  // TEST 1: GET Investigation without secret -> MUST FAIL 401
  const req1 = makeReq(baseUrl, 'GET');
  const res1 = await getInvestigation(req1, { params: { id: invId } });
  assert.strictEqual(res1.status, 401, 'GET investigation without secret must be 401');
  console.log('✓ PASS: GET /api/v1/investigations/[id] without secret rejected with 401');

  // TEST 2: GET Investigation with invalid secret -> MUST FAIL 401
  const req2 = makeReq(baseUrl, 'GET', { 'x-session-secret': 'invalid_secret_abc123' });
  const res2 = await getInvestigation(req2, { params: { id: invId } });
  assert.strictEqual(res2.status, 401, 'GET investigation with invalid secret must be 401');
  console.log('✓ PASS: GET /api/v1/investigations/[id] with invalid secret rejected with 401');

  // TEST 3: GET Investigation with valid secret -> MUST SUCCEED 200
  const req3 = makeReq(baseUrl, 'GET', { 'x-session-secret': secret });
  const res3 = await getInvestigation(req3, { params: { id: invId } });
  assert.strictEqual(res3.status, 200, 'GET investigation with valid secret must be 200');
  console.log('✓ PASS: GET /api/v1/investigations/[id] with valid secret succeeded with 200');

  // TEST 4: POST Evidence without secret -> MUST FAIL 401
  const req4 = makeReq(`${baseUrl}/evidence`, 'POST');
  const res4 = await postEvidence(req4, { params: { id: invId } });
  assert.strictEqual(res4.status, 401, 'POST evidence without secret must be 401');
  console.log('✓ PASS: POST /api/v1/investigations/[id]/evidence without secret rejected with 401');

  // TEST 5: POST Process without secret -> MUST FAIL 401
  const req5 = makeReq(`${baseUrl}/process`, 'POST');
  const res5 = await postProcess(req5, { params: { id: invId } });
  assert.strictEqual(res5.status, 401, 'POST process without secret must be 401');
  console.log('✓ PASS: POST /api/v1/investigations/[id]/process without secret rejected with 401');

  // TEST 6: POST Reports without secret -> MUST FAIL 401
  const req6 = makeReq(`${baseUrl}/reports`, 'POST');
  const res6 = await postReport(req6, { params: { id: invId } });
  assert.strictEqual(res6.status, 401, 'POST reports without secret must be 401');
  console.log('✓ PASS: POST /api/v1/investigations/[id]/reports without secret rejected with 401');

  // TEST 7: GET Reports without secret -> MUST FAIL 401
  const req7 = makeReq(`${baseUrl}/reports`, 'GET');
  const res7 = await getReport(req7, { params: { id: invId } });
  assert.strictEqual(res7.status, 401, 'GET reports without secret must be 401');
  console.log('✓ PASS: GET /api/v1/investigations/[id]/reports without secret rejected with 401');

  // TEST 8: GET Download without secret -> MUST FAIL 401
  const req8 = makeReq(`${baseUrl}/reports/RPT-FAKE1234/download`, 'GET');
  const res8 = await getDownload(req8, { params: { id: invId, reportId: 'RPT-FAKE1234' } });
  assert.strictEqual(res8.status, 401, 'GET report download without secret must be 401');
  console.log('✓ PASS: GET /api/v1/investigations/[id]/reports/[reportId]/download without secret rejected with 401');

  // TEST 9: DELETE Investigation without secret -> MUST FAIL 401
  const req9 = makeReq(baseUrl, 'DELETE');
  const res9 = await deleteInvestigation(req9, { params: { id: invId } });
  assert.strictEqual(res9.status, 401, 'DELETE investigation without secret must be 401');
  console.log('✓ PASS: DELETE /api/v1/investigations/[id] without secret rejected with 401');

  // TEST 10: DELETE Investigation with valid secret -> MUST SUCCEED 200
  const req10 = makeReq(baseUrl, 'DELETE', { 'x-session-secret': secret });
  const res10 = await deleteInvestigation(req10, { params: { id: invId } });
  assert.strictEqual(res10.status, 200, 'DELETE investigation with valid secret must be 200');
  console.log('✓ PASS: DELETE /api/v1/investigations/[id] with valid secret succeeded with 200');

  console.log('\n===============================================================');
  console.log('🎉 ALL 10 SECURITY AUTHORIZATION REGRESSION TESTS PASSED!');
  console.log('===============================================================\n');
}

runSecurityAuditTests().catch((err) => {
  console.error('Security audit test failed:', err);
  process.exit(1);
});
