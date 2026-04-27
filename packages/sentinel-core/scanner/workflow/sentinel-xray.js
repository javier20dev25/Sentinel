/**
 * Sentinel X-Ray: Runtime Monkey-Patching Interceptor
 * 
 * Injected automatically into the CI Sandbox environment to hook global primitives
 * (eval, Function, child_process.exec). It extracts malicious payloads hidden behind
 * Base64 obfuscation or packers directly from memory just before execution.
 */

const vm = require('vm');
const util = require('util');

const originalEval = global.eval;
const originalFunction = global.Function;

// Intercept global.eval
global.eval = function (code) {
    console.log(`\n======================================================`);
    console.log(`[SENTINEL X-RAY] 🚨 INTERCEPTED EVAL PAYLOAD 🚨`);
    console.log(`======================================================`);
    console.log(code);
    console.log(`======================================================\n`);
    
    // In a strict honeypot, we might block this entirely.
    // For Sandbox analysis, we let it run inside a VM context if needed or just return.
    return originalEval(code);
};

// Intercept new Function()
// Using a proxy to catch dynamic instantiations beautifully
global.Function = new Proxy(originalFunction, {
    construct(target, args) {
        const payload = args[args.length - 1]; // The function body
        console.log(`\n======================================================`);
        console.log(`[SENTINEL X-RAY] 🚨 INTERCEPTED 'new Function' PAYLOAD 🚨`);
        console.log(`======================================================`);
        console.log(payload);
        console.log(`======================================================\n`);
        return new target(...args);
    },
    apply(target, thisArg, args) {
        const payload = args[args.length - 1];
        console.log(`\n======================================================`);
        console.log(`[SENTINEL X-RAY] 🚨 INTERCEPTED 'Function()' PAYLOAD 🚨`);
        console.log(`======================================================`);
        console.log(payload);
        console.log(`======================================================\n`);
        return target.apply(thisArg, args);
    }
});

// Hook child_process
try {
    const cp = require('child_process');
    const originalExec = cp.exec;
    const originalSpawn = cp.spawn;

    cp.exec = function (command, ...args) {
        console.log(`\n[SENTINEL X-RAY] 🚨 INTERCEPTED OS COMMAND (exec) 🚨\nCMD: ${command}\n`);
        return originalExec.apply(this, [command, ...args]);
    };

    cp.spawn = function (command, args, options) {
        console.log(`\n[SENTINEL X-RAY] 🚨 INTERCEPTED OS COMMAND (spawn) 🚨\nCMD: ${command} ${args ? args.join(' ') : ''}\n`);
        return originalSpawn.apply(this, [command, args, options]);
    };
} catch (e) {
    // child_process not available/hookable
}

console.log("[SENTINEL X-RAY] Active Hunting Mode enabled. Global primitives monkey-patched.");
