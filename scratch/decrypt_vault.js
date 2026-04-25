const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const desktopPath = path.join(require('os').homedir(), 'OneDrive', 'Desktop');
const sourceFile = path.join(desktopPath, 'Sentinel_Oracle_Whitepaper.enc');
const targetFile = path.join(desktopPath, 'Sentinel_Oracle_Whitepaper_Decrypted.md');

const algorithm = 'aes-256-cbc';
const password = 'SentinelAppSecPro2026!'; // Master password
const key = crypto.scryptSync(password, 'salt', 32);

try {
    if (fs.existsSync(sourceFile)) {
        const input = fs.readFileSync(sourceFile);
        
        // The first 16 bytes are the IV
        const iv = input.subarray(0, 16);
        const encryptedData = input.subarray(16);
        
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        
        const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
        
        fs.writeFileSync(targetFile, decrypted);
        console.log(`\x1b[32m[+] Archivo desencriptado exitosamente a: ${targetFile}\x1b[0m`);
    } else {
        console.log(`\x1b[31m[-] No se encontró el archivo encriptado (.enc) en el escritorio.\x1b[0m`);
    }
} catch (error) {
    console.error('\x1b[31m[!] Error durante la desencriptación (¿Contraseña incorrecta?):\x1b[0m', error.message);
}
