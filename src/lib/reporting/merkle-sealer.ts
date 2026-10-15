import crypto from 'crypto';
import { ForensicArtifact, ForensicFinding } from '@/types/forensics';

function canonicalJsonStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((key) => `${JSON.stringify(key)}:${canonicalJsonStringify(obj[key])}`);
  return '{' + pairs.join(',') + '}';
}

export class MerkleSealer {
  /**
   * Build a cryptographic Merkle root hash from artifacts and findings
   */
  static generateMerkleRoot(artifacts: ForensicArtifact[], findings: ForensicFinding[]): string {
    const leaves: string[] = [];

    // Hash artifacts deterministically
    for (const art of artifacts) {
      const payloadString = canonicalJsonStringify({
        id: art.artifact_id,
        type: art.artifact_type,
        data: art.data_payload,
      });
      leaves.push(crypto.createHash('sha256').update(payloadString).digest('hex'));
    }

    // Hash findings deterministically
    for (const fnd of findings) {
      const findingString = canonicalJsonStringify({
        id: fnd.finding_id,
        title: fnd.title,
        artifacts: fnd.supporting_artifact_ids,
        rationale: fnd.technical_rationale,
      });
      leaves.push(crypto.createHash('sha256').update(findingString).digest('hex'));
    }

    if (leaves.length === 0) {
      return crypto.createHash('sha256').update('EMPTY_INVESTIGATION').digest('hex');
    }

    // Sort leaves deterministically
    leaves.sort();

    // Reduce leaves to Merkle Root
    let currentLevel = leaves;
    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          const combined = currentLevel[i] + currentLevel[i + 1];
          nextLevel.push(crypto.createHash('sha256').update(combined).digest('hex'));
        } else {
          nextLevel.push(currentLevel[i]);
        }
      }
      currentLevel = nextLevel;
    }

    return currentLevel[0];
  }
}
