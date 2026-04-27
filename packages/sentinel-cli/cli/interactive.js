'use strict';

const readline = require('readline');
const pc = require('picocolors');
const { spawnSync } = require('child_process');
const { printMetrics } = require('./telemetry');
const gh = require('../../sentinel-core/lib/gh_bridge');
const scanner = require('../../sentinel-core/scanner/index');

const FREE_TIER_LIMIT = 3;

// i18n Dictionary
const i18n = {
    en: {
        auth_title: 'Identity & Access',
        auth_no_session: 'No active session found.',
        auth_init: 'Initiating secure OAuth handshake...',
        auth_fail: 'Authentication failed:',
        auth_success: 'Authenticated as:',
        menu_title: 'Main Operations Menu',
        menu_opt1: 'Select Workspaces & Run Audits',
        menu_opt2: 'Sentinel Guard & Configuration (NPM Intercept)',
        menu_opt3: 'View CLI Manual & Run Commands',
        menu_opt4: 'Classified Documents',
        menu_opt5: 'Exit',
        select_opt: 'Select option',
        invalid_sel: 'Invalid selection.',
        workspace_title: 'Workspace Discovery',
        workspace_none: 'No repositories found.',
        workspace_retrieved: 'Retrieved {count} repositories (Free Tier Limit: {limit})',
        workspace_select: 'Select up to {limit} workspaces (e.g. 1,3) or type \'0\' to cancel:',
        workspace_limit: '⚠️ Free Tier is limited to {limit} repos at a time.',
        config_title: 'Sentinel Guard & Global Configuration',
        config_desc: 'OS-level interception for npm/pip and Trust Cache management.',
        config_opt1: 'Guard Status',
        config_opt2: 'Enable Guard (Intercept npm/yarn/pip)',
        config_opt3: 'Disable Guard',
        config_opt4: 'List Trust Cache (Whitelisted packages)',
        config_opt5: 'Back to Main Menu',
        target_title: 'TARGET:',
        target_vis: 'Visibility:',
        target_sync: 'Last Sync:',
        target_sel: 'Select Audit Vector',
        target_opt1: 'Run Baseline Context Scan',
        target_opt2: 'Audit Pull Requests',
        target_opt3: 'Cancel Target',
        target_dim1: '(Local Engine)',
        target_dim2: '(Surgical Inspection)',
        action: 'Action >',
        metrics_title: 'ORACLE PERFORMANCE & RESOURCE TELEMETRY',
        metrics_mem: 'Memory Footprint:',
        metrics_cpu: 'CPU Compute:',
        metrics_disk: 'Disk I/O:',
        metrics_net: 'Network Ingress:',
        metrics_energy: 'Energy Cost:',
        metrics_dim1: '[V8 GC Optimized]',
        metrics_dim2: '[Multi-thread Offload]',
        metrics_dim3: '[Streamed Buffer]',
        metrics_dim4: '[Threat Feed Sync]',
        metrics_dim5: '[Hardware Monitored]',
        scan_init: 'Initializing Sentinel Engine for {repo}...',
        scan_prog: 'Analyzing AST signatures and data flows...',
        scan_done: 'Baseline Context Analysis Completed.',
        scan_notice: '⚠️ Notice: Detailed threat vectors are hidden in CLI Free Tier. Check Web Dashboard.',
        press_enter: 'Press Enter to return...',
        pr_title: 'Pull Request Gateway',
        pr_none: 'No open Pull Requests. The perimeter is secure.',
        pr_cancel: 'Cancel',
        pr_target: 'Target ID >',
        pr_extract: 'Extracting surgical diff for PR #{num}...',
        pr_fail: 'Failed to extract diff. Payload might be corrupted or oversized.',
        pr_exec: 'Executing Surgical Inspection on dynamic payload...',
        pr_clean: 'VERDICT: CLEAN',
        pr_clean_desc: 'PR #{num} contains no known malicious signatures.',
        pr_threat: 'FATAL THREATS INTERCEPTED (PR #{num})',
        pr_threat_desc: 'Merging this code will critically compromise the system.',
        session_end: '👋 Session terminated securely.'
    },
    es: {
        auth_title: 'Identidad y Acceso',
        auth_no_session: 'No se encontró una sesión activa.',
        auth_init: 'Iniciando conexión segura OAuth...',
        auth_fail: 'Fallo de autenticación:',
        auth_success: 'Autenticado como:',
        menu_title: 'Menú Principal de Operaciones',
        menu_opt1: 'Seleccionar Repositorios y Ejecutar Auditorías',
        menu_opt2: 'Sentinel Guard y Configuración (Interceptar NPM)',
        menu_opt3: 'Ver Manual CLI y Ejecutar Comandos',
        menu_opt4: 'Documentos Clasificados',
        menu_opt5: 'Salir',
        select_opt: 'Selecciona una opción',
        invalid_sel: 'Selección inválida.',
        workspace_title: 'Descubrimiento de Espacios de Trabajo',
        workspace_none: 'No se encontraron repositorios.',
        workspace_retrieved: 'Se obtuvieron {count} repositorios (Límite Free Tier: {limit})',
        workspace_select: 'Selecciona hasta {limit} repositorios (ej. 1,3) o \'0\' para cancelar:',
        workspace_limit: '⚠️ El plan Free está limitado a {limit} repositorios a la vez.',
        config_title: 'Sentinel Guard y Configuración Global',
        config_desc: 'Intercepción a nivel de OS para npm/pip y gestión de Caché de Confianza.',
        config_opt1: 'Estado del Guard',
        config_opt2: 'Activar Guard (Interceptar npm/yarn/pip)',
        config_opt3: 'Desactivar Guard',
        config_opt4: 'Listar Caché de Confianza (Paquetes seguros)',
        config_opt5: 'Volver al Menú Principal',
        target_title: 'OBJETIVO:',
        target_vis: 'Visibilidad:',
        target_sync: 'Última Sincronización:',
        target_sel: 'Seleccionar Vector de Auditoría',
        target_opt1: 'Ejecutar Escaneo de Contexto Base',
        target_opt2: 'Auditar Pull Requests',
        target_opt3: 'Cancelar Objetivo',
        target_dim1: '(Motor Local)',
        target_dim2: '(Inspección Quirúrgica)',
        action: 'Acción >',
        metrics_title: 'TELEMETRÍA DE RENDIMIENTO Y RECURSOS ORACLE',
        metrics_mem: 'Consumo de Memoria:',
        metrics_cpu: 'Cómputo de CPU:',
        metrics_disk: 'E/S de Disco:',
        metrics_net: 'Tráfico de Red:',
        metrics_energy: 'Costo Energético:',
        metrics_dim1: '[Optimizado V8 GC]',
        metrics_dim2: '[Descarga Multi-hilo]',
        metrics_dim3: '[Buffer en Streaming]',
        metrics_dim4: '[Sincronización de Amenazas]',
        metrics_dim5: '[Monitoreado por HW]',
        scan_init: 'Inicializando Motor Sentinel para {repo}...',
        scan_prog: 'Analizando firmas AST y flujos de datos...',
        scan_done: 'Análisis de Contexto Base Completado.',
        scan_notice: '⚠️ Aviso: Los vectores de amenaza detallados están ocultos en la CLI (Free Tier). Revisa el Web Dashboard.',
        press_enter: 'Presiona Enter para volver...',
        pr_title: 'Puerta de Enlace de Pull Requests',
        pr_none: 'No hay Pull Requests abiertos. El perímetro es seguro.',
        pr_cancel: 'Cancelar',
        pr_target: 'ID del Objetivo >',
        pr_extract: 'Extrayendo diff quirúrgico para el PR #{num}...',
        pr_fail: 'Fallo al extraer el diff. El payload podría estar corrupto o ser demasiado grande.',
        pr_exec: 'Ejecutando Inspección Quirúrgica en payload dinámico...',
        pr_clean: 'VEREDICTO: LIMPIO',
        pr_clean_desc: 'El PR #{num} no contiene firmas maliciosas conocidas.',
        pr_threat: 'AMENAZAS FATALES INTERCEPTADAS (PR #{num})',
        pr_threat_desc: 'Hacer merge de este código comprometerá críticamente el sistema.',
        session_end: '👋 Sesión terminada de forma segura.'
    }
};

let lang = 'en';
const t = (key) => i18n[lang][key];

function askQuestion(query) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(query, ans => {
        rl.close();
        resolve(ans.trim());
    }));
}

function printHeader() {
    console.clear();
    // Fixed "SENTINEL" ASCII Art - Only Cyan
    const logo = [
        "  ██████  ███████ ███    ██ ████████ ██ ███    ██ ███████ ██      ",
        " ██       ██      ████   ██    ██    ██ ████   ██ ██      ██      ",
        "  ██████  █████   ██ ██  ██    ██    ██ ██ ██  ██ █████   ██      ",
        "       ██ ██      ██  ██ ██    ██    ██ ██  ██ ██ ██      ██      ",
        "  ██████  ███████ ██   ████    ██    ██ ██   ████ ███████ ███████ "
    ];
    
    console.log('');
    logo.forEach(line => {
        console.log(pc.cyan(pc.bold(line)));
    });
    console.log(pc.dim('                                           Oracle Engine v3.8\n'));
}

async function startInteractiveHub() {
    printHeader();
    
    // Language Selection
    console.log(pc.cyan('? ') + pc.bold('Language / Idioma'));
    console.log(pc.blue('  1.') + pc.white(' English'));
    console.log(pc.blue('  2.') + pc.white(' Español'));
    
    const langOpt = await askQuestion(pc.blue('  ❯ ') + pc.bold('Select option (1-2): '));
    lang = (langOpt === '2') ? 'es' : 'en';
    
    printHeader();

    // 1. Authentication
    console.log(pc.cyan('? ') + pc.bold(t('auth_title')));
    let auth = gh.checkAuth();
    
    if (!auth.authenticated) {
        console.log(pc.blue('  ❯ ') + pc.red(t('auth_no_session')));
        console.log(pc.blue('  ❯ ') + pc.dim(t('auth_init')));
        
        const loginResult = await gh.login();
        if (!loginResult.success) {
            console.log(pc.blue('  ❯ ') + pc.red(`❌ ${t('auth_fail')} ${loginResult.message}`));
            process.exit(1);
        }
        auth = { authenticated: true, username: loginResult.username };
    }

    console.log(pc.blue('  ❯ ') + pc.green('✔ ') + t('auth_success') + ' ' + pc.bold(pc.white(auth.username)) + '\n');

    while (true) {
        console.log(pc.cyan('? ') + pc.bold(t('menu_title')));
        console.log(pc.blue('  1.') + pc.white(` 📦 ${t('menu_opt1')}`));
        console.log(pc.blue('  2.') + pc.white(` ⚙️  ${t('menu_opt2')}`));
        console.log(pc.blue('  3.') + pc.white(` 📖 ${t('menu_opt3')}`));
        console.log(pc.blue('  4.') + pc.white(` 🔐 ${t('menu_opt4')}`));
        console.log(pc.blue('  5.') + pc.white(` 🚪 ${t('menu_opt5')}`));
        
        const mainAction = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('select_opt')} (1-5): `));

        if (mainAction === '1') {
            await handleWorkspaceDiscovery();
        } else if (mainAction === '2') {
            await handleConfigurationMenu();
        } else if (mainAction === '3') {
            await handleInteractiveShell();
        } else if (mainAction === '4') {
            const { handleClassifiedMenu } = require('./classify');
            await handleClassifiedMenu(lang);
            printHeader();
        } else if (mainAction === '5') {
            console.log(pc.cyan(`\n${t('session_end')}\n`));
            process.exit(0);
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}\n`));
        }
    }
}

async function handleWorkspaceDiscovery() {
    console.log('\n' + pc.cyan('? ') + pc.bold(t('workspace_title')));
    const allRepos = gh.listUserRepos(50);
    
    if (!allRepos || allRepos.length === 0) {
        console.log(pc.blue('  ❯ ') + pc.red(t('workspace_none')));
        return;
    }

    console.log(pc.blue('  ❯ ') + pc.dim(t('workspace_retrieved').replace('{count}', allRepos.length).replace('{limit}', FREE_TIER_LIMIT)));
    
    allRepos.forEach((repo, idx) => {
        const vis = repo.visibility === 'PUBLIC' ? pc.green('PUB') : pc.yellow('PRV');
        console.log(pc.blue('  │ ') + pc.dim(`[${String(idx + 1).padStart(2, ' ')}] `) + pc.inverse(` ${vis} `) + ' ' + pc.white(repo.fullName));
    });

    console.log(pc.blue('  │ '));
    let selectedIndices = [];
    while (true) {
        const input = await askQuestion(pc.blue('  ❯ ') + pc.bold(t('workspace_select').replace('{limit}', FREE_TIER_LIMIT) + ' '));
        if (input === '0') return;
        
        const parts = input.split(',').map(n => parseInt(n.trim()) - 1).filter(n => !isNaN(n) && n >= 0 && n < allRepos.length);
        
        if (parts.length === 0) {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        } else if (parts.length > FREE_TIER_LIMIT) {
            console.log(pc.yellow(`    ${t('workspace_limit').replace('{limit}', FREE_TIER_LIMIT)}`));
        } else {
            selectedIndices = parts;
            break;
        }
    }

    const selectedRepos = selectedIndices.map(i => allRepos[i]);

    for (const repo of selectedRepos) {
        await handleRepoMenu(repo);
    }
    console.clear();
    printHeader();
}

async function handleInteractiveShell() {
    console.clear();
    printHeader();
    console.log(pc.cyan('? ') + pc.bold(lang === 'es' ? 'Manual de Sentinel CLI' : 'Sentinel CLI Manual'));
    
    console.log(pc.blue('  ┌─ ') + pc.white(pc.bold('Comandos Principales (Core Commands)')));
    console.log(pc.blue('  │  ') + pc.cyan('sentinel scan <ruta> ') + pc.dim('   Escanea una ruta específica en busca de amenazas.'));
    console.log(pc.blue('  │  ') + pc.cyan('sentinel install <pkg>') + pc.dim('   Instala un paquete pasándolo por el Firewall.'));
    console.log(pc.blue('  │  ') + pc.cyan('sentinel prepush      ') + pc.dim('   Analiza el código antes de subirlo a GitHub (Bloquea .env).'));
    
    console.log(pc.blue('  ├─ ') + pc.white(pc.bold('Sentinel Guard (Intercepción SO)')));
    console.log(pc.blue('  │  ') + pc.cyan('sentinel guard enable ') + pc.dim('   Activa la protección global para NPM, PIP, Docker.'));
    console.log(pc.blue('  │  ') + pc.cyan('sentinel guard disable') + pc.dim('   Apaga el escudo de intercepción.'));
    
    console.log(pc.blue('  └─ ') + pc.white(pc.bold('Opciones Globales')));
    console.log(pc.blue('     ') + pc.cyan('--json                ') + pc.dim('   Salida en formato JSON para CI/CD.'));
    console.log(pc.blue('     ') + pc.cyan('--profile <perfil>    ') + pc.dim('   balanced, strict o dev.'));

    console.log('');
    while(true) {
        const cmd = await askQuestion(pc.blue('  ❯ ') + pc.bold(lang === 'es' ? 'Ejecutar comando (o "0" para volver): sentinel ' : 'Run command (or "0" to back): sentinel '));
        if (cmd === '0') {
            console.clear();
            printHeader();
            break;
        }
        if (cmd.trim() !== '') {
            const args = cmd.split(' ').map(s => s.trim()).filter(s => s.length > 0);
            console.log(pc.dim('\n  Ejecutando: sentinel ' + cmd + '...\n'));
            spawnSync('node', [__dirname + '/index.js', ...args], { stdio: 'inherit' });
            console.log('');
        }
    }
}

async function handleConfigurationMenu() {
    while (true) {
        console.log('\n' + pc.cyan('? ') + pc.bold(t('config_title')));
        console.log(pc.dim('  ' + t('config_desc')));
        
        console.log(pc.blue('  1.') + pc.white(` 🛡️  ${t('config_opt1')}`));
        console.log(pc.blue('  2.') + pc.white(` 🟢 ${t('config_opt2')}`));
        console.log(pc.blue('  3.') + pc.white(` 🔴 ${t('config_opt3')}`));
        console.log(pc.blue('  4.') + pc.white(` 📋 ${t('config_opt4')}`));
        console.log(pc.blue('  5.') + pc.white(` 🔙 ${t('config_opt5')}`));
        
        const action = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('select_opt')} (1-5): `));

        console.log('');
        if (action === '1') {
            spawnSync('node', [__dirname + '/index.js', 'guard', 'status'], { stdio: 'inherit' });
        } else if (action === '2') {
            spawnSync('node', [__dirname + '/index.js', 'guard', 'enable'], { stdio: 'inherit' });
        } else if (action === '3') {
            spawnSync('node', [__dirname + '/index.js', 'guard', 'disable'], { stdio: 'inherit' });
        } else if (action === '4') {
            spawnSync('node', [__dirname + '/index.js', 'trust', 'list'], { stdio: 'inherit' });
        } else if (action === '5') {
            console.clear();
            printHeader();
            break;
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        }
    }
}

async function handleRepoMenu(repo) {
    while (true) {
        console.log('\n' + pc.cyan('▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰'));
        console.log(pc.bold(`🎯 ${t('target_title')} `) + pc.cyan(repo.fullName));
        console.log(pc.dim(`${t('target_vis')} ${repo.visibility} | ${t('target_sync')} ${new Date(repo.updatedAt).toLocaleString()}`));
        console.log(pc.cyan('▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰') + '\n');
        
        console.log(pc.cyan('? ') + pc.bold(t('target_sel')));
        console.log(pc.blue('  1.') + pc.white(` 🔍 ${t('target_opt1')} `) + pc.dim(t('target_dim1')));
        console.log(pc.blue('  2.') + pc.white(` 🔀 ${t('target_opt2')} `) + pc.dim(t('target_dim2')));
        console.log(pc.blue('  3.') + pc.white(` 🔙 ${t('target_opt3')}\n`));
        
        const action = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('action')} `));

        if (action === '1') {
            await simulateFullScanMetrics(repo);
        } else if (action === '2') {
            await handlePRInspection(repo);
        } else if (action === '3') {
            break;
        } else {
            console.log(pc.red(`    ${t('invalid_sel')}`));
        }
    }
}

async function simulateFullScanMetrics(repo) {
    console.log(pc.yellow(`\n🚀 ${t('scan_init').replace('{repo}', repo.fullName)}`));
    
    const spinChars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let i = 0;
    const interval = setInterval(() => {
        process.stdout.write(`\r${pc.cyan(spinChars[i++ % spinChars.length])} ` + pc.dim(t('scan_prog')));
    }, 80);

    await new Promise(r => setTimeout(r, 2000));
    clearInterval(interval);
    console.log('\r' + ' '.repeat(60) + '\r');
    console.log(pc.green(`✔ ${t('scan_done')}`));

    printMetrics(lang);
    console.log(pc.yellow(t('scan_notice')));
    await askQuestion(pc.dim(`\n${t('press_enter')}`));
}

async function handlePRInspection(repo) {
    console.log('\n' + pc.cyan('? ') + pc.bold(t('pr_title')));
    const prs = gh.listPRs(repo.fullName);

    if (!prs || prs.length === 0) {
        console.log(pc.blue('  ❯ ') + pc.green(`✔ ${t('pr_none')}`));
        await askQuestion(pc.dim(`\n${t('press_enter')}`));
        return;
    }

    prs.forEach((pr, idx) => {
        const date = new Date(pr.updatedAt).toISOString().split('T')[0];
        console.log(pc.blue('  │ ') + pc.cyan(`[${idx + 1}]`) + ` #${pr.number} ${pc.white(pr.title)} ` + pc.dim(`(${pr.author?.login || 'unknown'}, ${date})`));
    });

    console.log(pc.blue('  │ ') + pc.cyan(`[${prs.length + 1}]`) + ` 🔙 ${t('pr_cancel')}`);
    
    const action = await askQuestion(pc.blue('  ❯ ') + pc.bold(`${t('pr_target')} `));
    const prIdx = parseInt(action) - 1;

    if (prIdx === prs.length) return;
    if (isNaN(prIdx) || prIdx < 0 || prIdx >= prs.length) {
        console.log(pc.red(`    ${t('invalid_sel')}`));
        return;
    }

    const selectedPR = prs[prIdx];
    console.log(pc.dim(`\n    ${t('pr_extract').replace('{num}', selectedPR.number)}`));
    
    const diff = gh.getPRDiff(repo.fullName, selectedPR.number);
    if (!diff) {
        console.log(pc.red(`    ${t('pr_fail')}`));
        return;
    }

    console.log(pc.cyan(`    ${t('pr_exec')}`));
    scanner.loadRules();
    
    const results = await scanner.scanFile(`PR #${selectedPR.number}.diff`, diff);

    if (results.alerts.length === 0) {
        console.log('\n' + pc.bgGreen(pc.black(` ✔ ${t('pr_clean')} `)));
        console.log(pc.green(`    ${t('pr_clean_desc').replace('{num}', selectedPR.number)}`));
    } else {
        console.log('\n' + pc.bgRed(pc.white(` 🚨 ${t('pr_threat').replace('{num}', selectedPR.number)} `)));
        console.log(pc.red(`    ${t('pr_threat_desc')}\n`));
        
        results.alerts.forEach(a => {
            const ruleName = a.type || a.ruleName || 'UNKNOWN_THREAT_VECTOR';
            console.log(`  ${pc.red('■')} ` + pc.bgRed(pc.white(` RISK: ${a.riskLevel}/10 `)) + ' ' + pc.bold(pc.red(ruleName)));
            console.log(`    ${pc.dim('↳ ' + a.description)}\n`);
        });
    }

    console.log('');
    printMetrics(lang);
    await askQuestion(pc.dim(`${t('press_enter')}`));
}

module.exports = { startInteractiveHub };
