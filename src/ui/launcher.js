#!/usr/bin/env node

/**
 * SENTINEL LAUNCHER
 * Cinematic startup sequence for the Sentinel Security Suite.
 * Boots backend (Express API) + frontend (Vite) with visual flair.
 */

'use strict';

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

// ─── ANSI Escape Codes ───
const ESC = '\x1b[';
const RESET = `${ESC}0m`;
const BOLD = `${ESC}1m`;
const DIM = `${ESC}2m`;
const ITALIC = `${ESC}3m`;
const GREEN = `${ESC}38;2;0;255;136m`;
const CYAN = `${ESC}38;2;0;200;255m`;
const RED = `${ESC}38;2;255;60;60m`;
const YELLOW = `${ESC}38;2;255;200;60m`;
const BLUE = `${ESC}38;2;80;140;255m`;
const PURPLE = `${ESC}38;2;160;100;255m`;
const WHITE = `${ESC}38;2;220;220;220m`;
const GRAY = `${ESC}38;2;100;100;100m`;
const BG_BLACK = `${ESC}48;2;10;10;15m`;

const HIDE_CURSOR = `${ESC}?25l`;
const SHOW_CURSOR = `${ESC}?25h`;
const CLEAR_LINE = `${ESC}2K\r`;

// ─── ASCII Art ───
const SENTINEL_LOGO = [
  `${CYAN}${BOLD}`,
  `   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     `,
  `   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     `,
  `   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     `,
  `   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     `,
  `   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗`,
  `   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝`,
  `${RESET}`,
];

const SHIELD = [
  `${GREEN}      ┌──────────┐`,
  `${GREEN}     ╱    ╱╲      ╲`,
  `${GREEN}    │    ╱  ╲      │`,
  `${GREEN}    │   ╱ ${WHITE}${BOLD}SH${GREEN} ╲     │`,
  `${GREEN}    │   ╲ ${WHITE}${BOLD}LD${GREEN} ╱     │`,
  `${GREEN}    │    ╲  ╱      │`,
  `${GREEN}     ╲    ╲╱      ╱`,
  `${GREEN}      ╲          ╱`,
  `${GREEN}       ╲        ╱`,
  `${GREEN}        ╲      ╱`,
  `${GREEN}         ╲    ╱`,
  `${GREEN}          ╲  ╱`,
  `${GREEN}           ╲╱${RESET}`,
];

// ─── Helpers ───
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function typewrite(text, color = WHITE) {
  return new Promise(async (resolve) => {
    for (const char of text) {
      process.stdout.write(`${color}${char}${RESET}`);
      await sleep(8 + Math.random() * 15);
    }
    resolve();
  });
}

function printLine(text) {
  process.stdout.write(`${text}\n`);
}

async function progressBar(label, duration, color = GREEN) {
  const width = 40;
  const steps = 30;
  const stepTime = duration / steps;

  for (let i = 0; i <= steps; i++) {
    const filled = Math.round((i / steps) * width);
    const empty = width - filled;
    const percent = Math.round((i / steps) * 100);
    const bar = `${color}${'█'.repeat(filled)}${GRAY}${'░'.repeat(empty)}${RESET}`;
    process.stdout.write(`${CLEAR_LINE}  ${DIM}${WHITE}${label}${RESET} ${bar} ${BOLD}${color}${percent}%${RESET}`);
    await sleep(stepTime);
  }
  process.stdout.write('\n');
}

async function statusLine(label, value, ok = true) {
  const icon = ok ? `${GREEN}●${RESET}` : `${RED}●${RESET}`;
  const valueColor = ok ? GREEN : RED;
  process.stdout.write(`  ${icon} ${DIM}${WHITE}${label}${RESET}`);
  await sleep(100 + Math.random() * 200);
  const dots = '.'.repeat(Math.max(1, 38 - label.length - value.length));
  printLine(`${GRAY}${dots}${RESET} ${BOLD}${valueColor}${value}${RESET}`);
}

// ─── Boot Sequence ───
async function boot() {
  process.stdout.write(HIDE_CURSOR);
  console.clear();

  // Phase 1: Logo reveal
  printLine('');
  for (const line of SENTINEL_LOGO) {
    printLine(line);
    await sleep(50);
  }

  printLine('');
  printLine(`   ${GRAY}${DIM}─────────────────────────────────────────────────────────────────${RESET}`);
  printLine(`   ${DIM}${WHITE}  S E C U R I T Y   S U I T E   ${GRAY}v1.0.0   ${DIM}${ITALIC}Local Web Edition${RESET}`);
  printLine(`   ${GRAY}${DIM}─────────────────────────────────────────────────────────────────${RESET}`);
  printLine('');
  
  await sleep(400);

  // Phase 2: System diagnostics
  await typewrite('  > Initializing security subsystems...', CYAN);
  printLine('');
  printLine('');

  await statusLine('Operating System', `${os.platform()} ${os.arch()}`, true);
  await statusLine('Node.js Runtime', process.version, true);
  
  const totalRAM = (os.totalmem() / (1024 ** 3)).toFixed(1);
  const freeRAM = (os.freemem() / (1024 ** 3)).toFixed(1);
  await statusLine('System Memory', `${freeRAM}GB free / ${totalRAM}GB total`, parseFloat(freeRAM) > 0.5);
  
  await statusLine('CPU Cores', `${os.cpus().length} threads`, true);
  await statusLine('User', os.userInfo().username, true);
  
  printLine('');
  await sleep(200);

  // Phase 3: Module loading
  await progressBar('Loading SPS Engine    ', 600, CYAN);
  await progressBar('Loading Asset Guard   ', 400, PURPLE);
  await progressBar('Loading Audit Trail   ', 350, BLUE);
  await progressBar('Loading Threat Scanner', 500, YELLOW);
  
  printLine('');
  await sleep(300);

  // Phase 4: Boot confirmation
  const bootMessages = [
    [`${GREEN}  [SPS]${RESET}`, 'Project Shield Module .................', 'ARMED'],
    [`${PURPLE} [SAG]${RESET}`, 'Asset Guard DLP Module ................', 'ARMED'],
    [`${BLUE} [SGA]${RESET}`, 'Global Audit Trail ....................', 'ACTIVE'],
    [`${YELLOW}[SCAN]${RESET}`, 'Static Analysis Engine ................', 'READY'],
    [`${RED} [FWL]${RESET}`, 'Push Firewall .........................', 'STANDBY'],
  ];

  for (const [module, dots, status] of bootMessages) {
    process.stdout.write(`  ${module} ${GRAY}${dots}${RESET}`);
    await sleep(150 + Math.random() * 200);
    printLine(` ${GREEN}${BOLD}${status}${RESET}`);
  }

  printLine('');
  printLine(`   ${GRAY}${DIM}─────────────────────────────────────────────────────────────────${RESET}`);
  printLine('');

  // Phase 5: Starting services
  await typewrite('  > Booting Sentinel Core API on port 3001...', GREEN);
  printLine('');
  await sleep(200);
  await typewrite('  > Booting Vite Dev Server on port 5173...', GREEN);
  printLine('');
  printLine('');

  // Launch backend
  const backendPath = path.join(__dirname, 'backend', 'server', 'index.js');
  const backend = spawn(process.execPath, [backendPath], {
    cwd: __dirname,
    stdio: 'pipe',
    env: { ...process.env, NODE_ENV: 'development' }
  });

  backend.stdout.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) printLine(`  ${GREEN}${DIM}[CORE]${RESET} ${WHITE}${msg}${RESET}`);
  });

  backend.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg && !msg.includes('ExperimentalWarning')) {
      printLine(`  ${RED}${DIM}[CORE]${RESET} ${RED}${msg}${RESET}`);
    }
  });

  // Wait for backend to boot
  await sleep(1500);

  // Launch Vite frontend
  const isWindows = process.platform === 'win32';
  const vite = spawn(isWindows ? 'npx.cmd' : 'npx', ['vite', '--host'], {
    cwd: __dirname,
    stdio: 'pipe',
    env: { ...process.env, FORCE_COLOR: '1' },
    shell: true,
  });

  vite.stdout.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) {
      // Highlight the URL
      const urlMatch = msg.match(/http:\/\/localhost:\d+/);
      if (urlMatch) {
        printLine('');
        printLine(`  ${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}`);
        printLine(`  ${GREEN}${BOLD}║                                                  ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║  ${WHITE}${BOLD}SENTINEL IS LIVE${RESET}${GREEN}${BOLD}                                ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║                                                  ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║  ${CYAN}${BOLD}${urlMatch[0]}${RESET}${GREEN}${BOLD}                      ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║                                                  ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║  ${DIM}${WHITE}Open this URL in your browser to begin.${RESET}${GREEN}${BOLD}         ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║  ${WHITE}${BOLD}Press ${YELLOW}[ENTER]${WHITE} to launch dashboard.${RESET}${GREEN}${BOLD}            ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║  ${DIM}${WHITE}Press ${YELLOW}Ctrl+C${DIM}${WHITE} to shutdown all services.${RESET}${GREEN}${BOLD}       ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}║                                                  ║${RESET}`);
        printLine(`  ${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}`);
        printLine('');
        
        // Setup input for "Press Enter"
        process.stdin.resume();
        process.stdin.setEncoding('utf8');
        const onData = (data) => {
          if (data.toString().includes('\r') || data.toString().includes('\n')) {
             const url = urlMatch[0];
             const startCmd = process.platform === 'win32' ? 'start' : (process.platform === 'darwin' ? 'open' : 'xdg-open');
             spawn(startCmd, [url], { shell: true, detached: true }).unref();
             printLine(`  ${CYAN}> Launching default browser at ${url}...${RESET}`);
          }
        };
        process.stdin.on('data', onData);
        
        process.stdout.write(SHOW_CURSOR);
      }
    }
  });

  vite.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg && !msg.includes('Warning') && !msg.includes('MODULE_TYPELESS')) {
      printLine(`  ${YELLOW}${DIM}[VITE]${RESET} ${YELLOW}${msg}${RESET}`);
    }
  });

  // Graceful shutdown
  const cleanup = () => {
    printLine('');
    printLine(`  ${RED}${BOLD}> Shutting down Sentinel...${RESET}`);
    backend.kill('SIGTERM');
    vite.kill('SIGTERM');
    setTimeout(() => {
      printLine(`  ${GREEN}> All services terminated. Stay safe.${RESET}`);
      printLine('');
      process.stdout.write(SHOW_CURSOR);
      process.exit(0);
    }, 500);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  backend.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      printLine(`  ${RED}[CORE] Backend exited with code ${code}${RESET}`);
    }
  });

  vite.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      printLine(`  ${RED}[VITE] Frontend exited with code ${code}${RESET}`);
    }
    cleanup();  
  });
}

// ─── Run ───
boot().catch(err => {
  process.stdout.write(SHOW_CURSOR);
  console.error(`${RED}${BOLD}Fatal: ${err.message}${RESET}`);
  process.exit(1);
});
