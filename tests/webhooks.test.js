const crypto = require('crypto');
const webhookHandler = require('../src/ui/backend/lib/webhooks');

describe('Sentinel 3.6: Webhook Handling', () => {
    
    it('verifySignature validates a correct signature', () => {
        const payload = { action: 'opened', pull_request: { number: 1 } };
        const secret = 'dummy_secret';
        webhookHandler.secret = secret; // mock secret
        
        const hmac = crypto.createHmac('sha256', secret);
        const digest = 'sha256=' + hmac.update(JSON.stringify(payload)).digest('hex');
        
        const req = {
            body: payload,
            headers: {
                'x-hub-signature-256': digest
            }
        };
        
        expect(webhookHandler.verifySignature(req)).toBe(true);
    });

    it('verifySignature rejects an incorrect signature', () => {
        const payload = { action: 'opened' };
        webhookHandler.secret = 'dummy_secret';
        
        const req = {
            body: payload,
            headers: {
                'x-hub-signature-256': 'sha256=invalid_hash_value'
            }
        };
        
        expect(webhookHandler.verifySignature(req)).toBe(false);
    });
});
