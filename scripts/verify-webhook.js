/**
 * Ghost-Tag Webhook Signature Verification Utility
 * 
 * Validates incoming webhook payloads against an HMAC-SHA256 signature
 * using a shared webhook secret token (compatible with GitHub X-Hub-Signature-256).
 */

const crypto = require('crypto');

/**
 * Verify HMAC-SHA256 webhook signature
 * @param {string|Buffer} rawPayload - Unmodified raw request body string or buffer
 * @param {string} signatureHeader - Value of X-Hub-Signature-256 (e.g. 'sha256=abcdef...')
 * @param {string} secretKey - Shared webhook secret
 * @returns {boolean} - True if signature is cryptographically valid
 */
function verifyWebhookSignature(rawPayload, signatureHeader, secretKey) {
  if (!rawPayload || !signatureHeader || !secretKey) {
    return false;
  }

  const parts = signatureHeader.split('=');
  if (parts.length !== 2 || parts[0] !== 'sha256') {
    return false;
  }

  const expectedSignature = parts[1];
  const hmac = crypto.createHmac('sha256', secretKey);
  hmac.update(rawPayload);
  const calculatedSignature = hmac.digest('hex');

  const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
  const calculatedBuffer = Buffer.from(calculatedSignature, 'utf8');

  if (expectedBuffer.length !== calculatedBuffer.length) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(expectedBuffer, calculatedBuffer);
}

module.exports = { verifyWebhookSignature };

// CLI self-test execution
if (require.main === module) {
  const secret = 'ghost-tag-webhook-secret-token-sample';
  const testPayload = JSON.stringify({ event: 'release', version: '2.0.0', status: 'published' });
  const hmac = crypto.createHmac('sha256', secret).update(testPayload).digest('hex');
  const validHeader = `sha256=${hmac}`;

  const isValid = verifyWebhookSignature(testPayload, validHeader, secret);
  const isInvalid = verifyWebhookSignature(testPayload, 'sha256=badsignature1234567890abcdef', secret);

  if (isValid && !isInvalid) {
    console.log('[Ghost-Tag] Webhook HMAC-SHA256 verification test: PASSED (Constant-time safe)');
    process.exit(0);
  } else {
    console.error('[Ghost-Tag] Webhook verification test: FAILED');
    process.exit(1);
  }
}
