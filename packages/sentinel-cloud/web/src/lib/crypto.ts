/**
 * Sentinel: Master Encryption Layer (AES-256-GCM)
 */

import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;

function getKey(): Buffer {
  const key = process.env.SENTINEL_ENCRYPTION_KEY;
  if (!key) {
    throw new Error('SENTINEL_ENCRYPTION_KEY is not defined in environment variables');
  }
  // If key is in hex, convert to buffer, otherwise hash it to ensure 32 bytes
  if (key.length === 64) {
    return Buffer.from(key, 'hex');
  }
  return crypto.createHash('sha256').update(key).digest();
}

/**
 * Encrypts a JS object or string using AES-256-GCM
 */
export function encrypt(data: unknown): string {
  const text = typeof data === 'string' ? data : JSON.stringify(data);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Format: iv:authTag:encrypted
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypts a string back into an object or raw string
 */
export function decrypt(cipherText: string): unknown {
  try {
    const [ivHex, authTagHex, encryptedHex] = cipherText.split(':');
    
    if (!ivHex || !authTagHex || !encryptedHex) {
      throw new Error('Invalid cipher text format');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Decryption failed';
    console.error('Decryption error:', message);
    return null;
  }
}
