/**
 * Sentinel: Electron Main Process (HARDENED + RESILIENT)
 * 
 * SECURITY: contextIsolation enabled, nodeIntegration disabled.
 * Renderer process cannot access Node.js APIs directly.
 * All IPC communication goes through the preload.js bridge.
 * 
 * RESILIENCE: Each backend service is loaded independently with
 * individual try/catch blocks. Native module loading is handled
 * with explicit ASAR unpacked path resolution.
 * 
 * Audit: VULN-002 remediated — Electron security best practices applied.
 */

'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');

// ─── GLOBAL CRASH HANDLERS ───
// Prevent the app from silently dying on unhandled errors
process.on('uncaughtException', (err) => {
  try {
    const crashLog = path.join(
      app.getPath('userData'),
      'sentinel-crash.log'
    );
    const entry = `[${new Date().toISOString()}] UNCAUGHT EXCEPTION: ${err.message}\n${err.stack}\n\n`;
    fs.appendFileSync(crashLog, entry);
  } catch (_) { /* can't even log, just survive */ }
});

process.on('unhandledRejection', (reason) => {
  try {
    const crashLog = path.join(
      app.getPath('userData'),
      'sentinel-crash.log'
    );
    const entry = `[${new Date().toISOString()}] UNHANDLED REJECTION: ${reason}\n\n`;
    fs.appendFileSync(crashLog, entry);
  } catch (_) { /* survive */ }
});

// Reliable dev detection
const isDev = !app.isPackaged;

// ─── CLI ARGUMENT PARSING ───
const args = process.argv.slice(app.isPackaged ? 1 : 2);
const cliCommands = ['link', 'list', 'scan', 'open', 'version', '--version', '-v'];
const isCliAction = args.length > 0 && cliCommands.some(cmd => args[0].includes(cmd) || cmd === args[0]);

if (isCliAction) {
  try {
    const fakeArgv = app.isPackaged 
        ? [process.argv[0], 'index.js', ...process.argv.slice(1)] 
        : process.argv;
    const cli = require('../cli/index.js');
    cli.run(fakeArgv);
  } catch (e) {
    console.error("❌ CLI Error:", e.message);
    app.quit();
    process.exit(1);
  }
  return;
}

// ─── SINGLE INSTANCE LOCK ───
if (!isCliAction) {
  const gotTheLock = app.requestSingleInstanceLock();

  if (!gotTheLock) {
    app.quit();
  } else {
    app.on('second-instance', (event, commandLine) => {
      // Handle opening from CLI when already running
      const wins = BrowserWindow.getAllWindows();
      if (wins.length > 0) {
        if (wins[0].isMinimized()) wins[0].restore();
        wins[0].focus();
      }
    });
  }

  function createWindow() {
    const mainWindow = new BrowserWindow({
      width: 1280,
      height: 800,
      minWidth: 1024,
      minHeight: 768,
      title: "Sentinel Security Suite",
      autoHideMenuBar: true,
      backgroundColor: '#0a0a0c',
      icon: path.join(__dirname, '../public/sentinel-icon.png'),
      webPreferences: {
        // ─── SECURITY HARDENING ───
        nodeIntegration: false,      
        contextIsolation: true,      
        preload: path.join(__dirname, 'preload.js'),  
        sandbox: true,               
        webSecurity: true,           
        allowRunningInsecureContent: false,
      }
    });

    if (isDev) {
      const loadDevURL = () => {
        mainWindow.loadURL('http://localhost:5173').catch(() => {
          setTimeout(loadDevURL, 500);
        });
      };
      loadDevURL();
    } else {
      const indexPath = app.isPackaged
        ? path.join(process.resourcesPath, 'app.asar', 'dist', 'index.html')
        : path.join(__dirname, '../../dist/index.html');
        
      mainWindow.loadFile(indexPath).catch(err => {
        console.error("Failed to load index.html:", err);
      });
    }
  }

  app.whenReady().then(async () => {
    // ─── Backend Logging System (SAFE) ───
    const logPath = path.join(app.getPath('userData'), 'sentinel-backend.log');
    
    // Log Rotation: Truncate if > 5MB
    if (fs.existsSync(logPath)) {
      const stats = fs.statSync(logPath);
      if (stats.size > 5 * 1024 * 1024) {
        fs.writeFileSync(logPath, `[${new Date().toISOString()}] Log truncated at startup\n`);
      }
    }

    const logStream = fs.createWriteStream(logPath, { flags: 'a' });
    const originalConsoleLog = console.log.bind(console);
    const originalConsoleError = console.error.bind(console);

    function log(msg) {
        const entry = `[${new Date().toISOString()}] ${msg}\n`;
        logStream.write(entry);
        originalConsoleLog(msg);
    }
    
    log('--- SENTINEL BACKEND STARTUP ---');
    
    // Path resolution for packaged mode
    const appRoot = app.isPackaged ? app.getAppPath() : path.join(__dirname, '..');
    
    if (app.isPackaged) {
      const unpackedPath = appRoot.replace('app.asar', 'app.asar.unpacked');
      const unpackedNodeModules = path.join(unpackedPath, 'node_modules');
      if (fs.existsSync(unpackedNodeModules)) {
        require('module').globalPaths.unshift(unpackedNodeModules);
        log(`Added unpacked node_modules to search path: ${unpackedNodeModules}`);
      }
    }
    
    // Override console for backend logging
    console.log = (...args) => log(`[BACKEND] ${args.join(' ')}`);
    console.error = (...args) => {
        log(`[ERR] ${args.join(' ')}`);
        originalConsoleError(...args);
    };

    // ─── Load Backend Server ───
    try {
      const serverPath = path.join(appRoot, 'backend', 'server', 'index.js');
      require(serverPath);
      log('Backend API server loaded.');
    } catch (e) {
      log(`BACKEND SERVER FAIL: ${e.message}`);
    }

    // ─── Health Check before Window ───
    await new Promise((resolve) => {
      let attempts = 0;
      const check = () => {
        const req = require('http').get('http://127.0.0.1:3001/api/auth/local/status', (res) => {
          resolve();
        });
        req.on('error', () => {
          attempts++;
          if (attempts < 30) setTimeout(check, 200);
          else resolve();
        });
        req.end();
      };
      check();
    });

    createWindow();

    ipcMain.on('app-quit', () => app.quit());
    ipcMain.handle('clear-memory', async () => {
      const wins = BrowserWindow.getAllWindows();
      for (const win of wins) {
        await win.webContents.session.clearCache();
        await win.webContents.session.clearStorageData();
      }
      return { success: true };
    });

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
