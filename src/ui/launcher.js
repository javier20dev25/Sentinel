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

function hslToRgb(h, s, l) {
  s /= 100;
  l /= 100;
  const k = n => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = n => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return [Math.round(255 * f(0)), Math.round(255 * f(8)), Math.round(255 * f(4))];
}

function getRgbAnsi(h) {
  const [r, g, b] = hslToRgb(h, 100, 50);
  return `\x1b[38;2;${r};${g};${b}m`;
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
  const viteCmd = isWindows ? 'npx.cmd vite --host' : 'npx vite --host';
  const vite = spawn(viteCmd, {
    cwd: __dirname,
    stdio: 'pipe',
    env: { ...process.env, FORCE_COLOR: '1' },
    shell: true,
  });

  let isLive = false;
  let autoOpenTimeout;
  let interval;

  const showBox = (url = 'http://localhost:5173') => {
    if (isLive) return;
    isLive = true;
    if (fallbackTimeout) clearTimeout(fallbackTimeout);

    let hue = 0;
    const printStaticBox = () => {
      const color = CYAN;
      process.stdout.write(`\n  ${color}${BOLD}╔══════════════════════════════════════════════════╗${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║                                                  ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║  ${WHITE}${BOLD}SENTINEL IS LIVE${RESET}${color}${BOLD}                                ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║                                                  ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║  ${CYAN}${BOLD}${url}${RESET}${color}${BOLD}                      ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║                                                  ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║  ${DIM}${WHITE}Open this URL in your browser to begin.${RESET}${color}${BOLD}         ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║  ${WHITE}${BOLD}Press ${YELLOW}[ANY KEY]${WHITE} to launch dashboard.${RESET}${color}${BOLD}           ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}║  ${DIM}${WHITE}Automating launch in 4s...${RESET}${color}${BOLD}                      ║${RESET}\n`);
      process.stdout.write(`  ${color}${BOLD}╚══════════════════════════════════════════════════╝${RESET}\n`);
    };

    printStaticBox();

    const launchBrowser = () => {
      if (autoOpenTimeout) clearTimeout(autoOpenTimeout);
      if (interval) clearInterval(interval);
      
      const isWin = process.platform === 'win32';
      const cmd = isWin ? `start "" "${url}"` : (process.platform === 'darwin' ? `open "${url}"` : `xdg-open "${url}"`);
      
      spawn(cmd, { shell: true, detached: true }).unref();
      printLine(`\n  ${CYAN}${BOLD}> Launching Dashboard at ${url}...${RESET}\n`);
      if (process.stdin.setRawMode) process.stdin.setRawMode(false);
      process.stdin.pause();
    };

    // Auto-open after 4 seconds
    autoOpenTimeout = setTimeout(() => {
      printLine(`\n  ${YELLOW}> Auto-launching...${RESET}`);
      launchBrowser();
    }, 4000);

    // Setup input for "Press Any Key"
    if (process.stdin.setRawMode) {
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.on('data', (key) => {
        if (key.toString() === '\u0003') { // Ctrl+C
          cleanup();
          return;
        }
        launchBrowser();
      });
    }
    
    process.stdout.write(SHOW_CURSOR);
  };

  // Fallback: If Vite doesn't output a URL in 5s, show the box anyway
  const fallbackTimeout = setTimeout(() => {
    if (!isLive) {
      printLine(`  ${GRAY}${DIM}[VITE] Detection timeout. Forcing UI link...${RESET}`);
      showBox();
    }
  }, 5000);

  vite.stdout.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg && !isLive) {
      const urlMatch = msg.match(/http:\/\/localhost:\d+/);
      if (urlMatch) {
         showBox(urlMatch[0]);
      }
    }
  });

  vite.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) {
      if (msg.includes('Error') || msg.includes('failed')) {
        printLine(`  ${RED}${DIM}[VITE-ERR]${RESET} ${YELLOW}${msg}${RESET}`);
      } else if (!msg.includes('Warning') && !msg.includes('MODULE_TYPELESS')) {
        printLine(`  ${GRAY}${DIM}[VITE-STDERR]${RESET} ${msg}${RESET}`);
      }
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
