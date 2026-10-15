import crypto from 'crypto';
import { ForensicEngine, ForensicExecutionContext, EngineResult } from '../types';

export class CryptographicHashingEngine implements ForensicEngine {
  engineId = 'engine-hashing';
  name = 'Multi-Algorithm Cryptographic Integrity Engine';
  version = '2.1.0';

  supports(_context: ForensicExecutionContext): boolean {
    return true; // Runs on all evidence
  }

  async execute(context: ForensicExecutionContext): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const buf = context.fileBuffer;

    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const sha1 = crypto.createHash('sha1').update(buf).digest('hex');
    const md5 = crypto.createHash('md5').update(buf).digest('hex');

    // Block hash / Chunk distribution (e.g. 4 chunks for integrity sampling)
    const chunkSize = Math.max(1, Math.floor(buf.length / 4));
    const blockHashes = [];
    for (let i = 0; i < 4 && i * chunkSize < buf.length; i++) {
      const chunk = buf.slice(i * chunkSize, Math.min(buf.length, (i + 1) * chunkSize));
      blockHashes.push({
        block_index: i,
        byte_range: `${i * chunkSize}-${Math.min(buf.length, (i + 1) * chunkSize) - 1}`,
        sha256: crypto.createHash('sha256').update(chunk).digest('hex'),
      });
    }

    const artifacts = [
      {
        artifact_type: 'CRYPTOGRAPHIC_HASHES',
        name: 'Cryptographic Hash Digests',
        category: 'IDENTIFICATION' as const,
        data_payload: {
          sha256,
          sha1,
          md5,
          total_bytes_hashed: buf.length,
          block_hashes: blockHashes,
          primary_algorithm: 'SHA-256 (NIST FIPS 180-4)',
          compatibility_algorithms: ['SHA-1', 'MD5'],
          cryptographic_preservation_note: 'SHA-256 is the authoritative integrity digest; MD5 and SHA-1 are recorded strictly for legacy database correlation.',
        },
      },
    ];

    const endTime = new Date().toISOString();
    const durationMs = new Date(endTime).getTime() - new Date(startTime).getTime();

    return {
      stage: {
        stage_name: 'CRYPTOGRAPHIC_HASHING',
        stage_order: context.stageOrder,
        tool_name: this.name,
        tool_version: this.version,
        status: 'SUCCESS',
        start_time: startTime,
        end_time: endTime,
        duration_ms: durationMs,
        execution_metadata: {
          sha256,
          sha1,
          md5,
          bytes_processed: buf.length,
        },
        warnings: [],
        errors: [],
      },
      artifacts,
      timelineEvents: [],
      findings: [],
      warnings: [],
      limitations: [],
    };
  }
}
