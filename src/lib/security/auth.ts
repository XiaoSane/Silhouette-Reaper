import crypto from 'crypto';

/**
 * Generate a cryptographically random investigation ID in the format INV-YYYY-XXXXXXXX
 */
export function generateInvestigationId(): string {
  const year = new Date().getFullYear();
  const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `INV-${year}-${randomHex}`;
}

/**
 * Generate high-entropy 256-bit session secret
 */
export function generateSessionSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hash session secret before database storage
 */
export function hashSessionSecret(secret: string): string {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

/**
 * Constant-time verification of session secrets to prevent timing attacks
 */
export function verifySessionSecret(providedSecret: string, storedHash: string): boolean {
  if (!providedSecret || !storedHash) return false;
  const providedHash = hashSessionSecret(providedSecret);
  const bufA = Buffer.from(providedHash, 'hex');
  const bufB = Buffer.from(storedHash, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generate structured entity IDs
 */
export function generateEntityId(prefix: 'EVD' | 'JOB' | 'STG' | 'ART' | 'TLE' | 'FND' | 'AUD' | 'RPT' | 'HSH'): string {
  const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}-${randomHex}`;
}

/**
 * Generate a public report verification token (e.g. VRF-9X4A-8B2K-7P1M)
 */
export function generateVerificationToken(): string {
  const p1 = crypto.randomBytes(2).toString('hex').toUpperCase();
  const p2 = crypto.randomBytes(2).toString('hex').toUpperCase();
  const p3 = crypto.randomBytes(2).toString('hex').toUpperCase();
  return `VRF-${p1}-${p2}-${p3}`;
}

/**
 * Sanitize untrusted filenames to prevent Path Traversal and Shell Injection
 */
export function sanitizeFilename(filename: string): string {
  if (!filename) return 'unnamed_evidence.bin';
  
  // Strip directory paths
  let clean = filename.replace(/^.*[\\\/]/, '');
  // Strip null bytes and control chars
  clean = clean.replace(/[\x00-\x1f\x80-\x9f]/g, '');
  // Replace unsafe characters
  clean = clean.replace(/[^a-zA-Z0-9._-]/g, '_');
  // Avoid leading dots or empty names
  clean = clean.replace(/^\.+/, '');
  if (!clean || clean.length > 200) {
    clean = `evidence_${Date.now().toString(36)}.bin`;
  }
  return clean;
}
