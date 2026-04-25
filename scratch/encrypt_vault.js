const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const desktopPath = path.join(require('os').homedir(), 'OneDrive', 'Desktop');
const sourceFile = path.join(desktopPath, 'Sentinel_Oracle_Whitepaper.md');
const targetFile = path.join(desktopPath, 'Sentinel_Oracle_Whitepaper.enc');

// We use a strong key for AES-256-CBC encryption
const algorithm = 'aes-256-cbc';
const password = 'SentinelAppSecPro2026!'; // The user's master password
const key = crypto.scryptSync(password, 'salt', 32);
const iv = crypto.randomBytes(16);

try {
    if (fs.existsSync(sourceFile)) {
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        const input = fs.readFileSync(sourceFile);
        
        // The encrypted file will have the IV at the beginning so we can decrypt it later
        const encrypted = Buffer.concat([iv, cipher.update(input), cipher.final()]);
        
        fs.writeFileSync(targetFile, encrypted);
        console.log(`\x1b[32m[+] Archivo encriptado exitosamente a: ${targetFile}\x1b[0m`);
        
        // Secure Delete (Overwrite with zeros before unlinking)
        const stats = fs.statSync(sourceFile);
        const zeroBuffer = Buffer.alloc(stats.size, 0);
        fs.writeFileSync(sourceFile, zeroBuffer); // Overwrite
        fs.unlinkSync(sourceFile); // Delete
        
        console.log(`\x1b[32m[+] Archivo original (.md) destruido de forma segura.\x1b[0m`);
        console.log(`\x1b[33m[*] La clave para desencriptar es: ${password}\x1b[0m`);
    } else {
        console.log(`\x1b[31m[-] El archivo original no se encontró en el escritorio.\x1b[0m`);
    }
} catch (error) {
    console.error('Error durante la encriptación:', error);
}
