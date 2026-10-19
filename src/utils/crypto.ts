import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { config } from '../config/index.js';

/**
 * Generate a random API key
 */
export function generateApiKey(): string {
  const randomPart = randomBytes(config.apiKey.length).toString('hex').slice(0, config.apiKey.length);
  return `${config.apiKey.prefix}${randomPart}`;
}

/**
 * Extract prefix from API key
 */
export function extractApiKeyPrefix(apiKey: string): string {
  return apiKey.slice(0, 12);
}

/**
 * Hash an API key for storage
 *
 * Uses scrypt — a memory-hard key derivation function — instead of a plain
 * fast hash so that a leaked hash cannot be brute-forced cheaply.
 */
export function hashApiKey(apiKey: string): string {
  const salt = config.apiKey.hashSecret ?? 'scraperx-default-hash-secret';
  return scryptSync(apiKey, salt, 32).toString('hex');
}

/**
 * Verify an API key against its hash
 */
export function verifyApiKey(apiKey: string, hash: string): boolean {
  const computedHash = hashApiKey(apiKey);
  const hashBuffer = Buffer.from(hash, 'hex');
  const computedBuffer = Buffer.from(computedHash, 'hex');
  
  if (hashBuffer.length !== computedBuffer.length) {
    return false;
  }
  
  return timingSafeEqual(hashBuffer, computedBuffer);
}

/**
 * Hash a URL for deduplication
 */
export function hashUrl(url: string): string {
  return createHash('sha256').update(url).digest('hex');
}

/**
 * Generate a unique job ID
 */
export function generateJobId(): string {
  const timestamp = Date.now().toString(36);
  const random = randomBytes(8).toString('hex');
  return `job_${timestamp}${random}`;
}

/**
 * Generate a unique batch ID
 */
export function generateBatchId(): string {
  const timestamp = Date.now().toString(36);
  const random = randomBytes(6).toString('hex');
  return `batch_${timestamp}${random}`;
}

/**
 * Generate a random string
 */
export function generateRandomString(length: number): string {
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}

/**
 * Hash content for deduplication
 */
export function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}
