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
  // Don't exit — let the app continue if possible
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
  // If it's a CLI action, we execute it directly and exit.
  // Note: 'open' is a CLI command handled by commander in cli/index.js,
  // which will send an HTTP post intent or spawn the GUI if needed.
  try {
    const fakeArgv = app.isPackaged 
        ? [process.argv[0], 'index.js', ...process.argv.slice(1)] 
        : process.argv;
    const cli = require('../cli/index.js');
    cli.run(fakeArgv);
    // Commander may do async operations so we don't quit immediately if there's an action,
    // but passive commands like version don't wait.
  } catch (e) {
    console.error("❌ CLI Error:", e.message);
    app.quit();
    process.exit(1);
  }
  // Commander processes async. We rely on the CLI commands to call process.exit(0) when done.
  // We return here to prevent the rest of the Electron app from initializing in this process.
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
      
      // Process CLI intents from second instance if needed
      const secondArgs = commandLine.slice(app.isPackaged ? 1 : 2);
      if (secondArgs.length > 0) {
        console.log("Second instance args:", secondArgs);
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
        nodeIntegration: false,      // Renderer CANNOT use require()
        contextIsolation: true,      // Renderer runs in isolated context
        preload: path.join(__dirname, 'preload.js'),  // Minimal API bridge
        sandbox: true,               // Enable Chromium sandbox
        webSecurity: true,           // Enforce same-origin policy
        allowRunningInsecureContent: false,
      }
    });

    if (isDev) {
      const loadDevURL = () => {
        mainWindow.loadURL('http://localhost:5173').catch(err => {
          console.warn("⚠️ Vite dev server not ready yet, retrying in 500ms...");
          setTimeout(loadDevURL, 500);
        });
      };
      loadDevURL();
    } else {
      const indexPath = app.isPackaged
        ? path.join(process.resourcesPath, 'app.asar', 'dist', 'index.html')
        : path.join(__dirname, '../../dist/index.html');
        
      console.log(`🛡️ Loading UI from: ${indexPath}`);
      mainWindow.loadFile(indexPath).catch(err => {
        console.error("Failed to load index.html:", err);
      });
    }

    // Debugging support
    mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
      console.error(`❌ UI Failed to load: ${errorCode} - ${errorDescription} (${validatedURL})`);
    });
  }

  app.whenReady().then(async () => {
    // ─── Backend Logging System (SAFE) ───
    const logPath = path.join(app.getPath('userData'), 'sentinel-backend.log');
    
    // Log Rotation: Truncate if > 5MB
    if (fs.existsSync(logPath)) {
      const stats = fs.statSync(logPath);
      if (stats.size > 5 * 1024 * 1024) {
        fs.writeFileSync(logPath, `[${new Date().toISOString()}] Log truncated at startup (was ${Math.round(stats.size/1024/1024)}MB)\n`);
      }
    }

    const logStream = fs.createWriteStream(logPath, { flags: 'a' });
    
    // Store original console methods before any override
    const originalConsoleLog = console.log.bind(console);
    const originalConsoleError = console.error.bind(console);

    function log(msg) {
        const entry = `[${new Date().toISOString()}] ${msg}\n`;
        logStream.write(entry);
        originalConsoleLog(msg); // SAFE: Use original method to avoid recursion
    }
    
    log('--- SENTINEL BACKEND STARTUP ---');
    log(`App Path: ${app.getAppPath()}`);
    log(`UserData Path: ${app.getPath('userData')}`);
    log(`Is Packaged: ${app.isPackaged}`);

    // Initialize backend services AFTER app is ready
    // RESILIENCE: Each service is loaded individually so one failure
    // doesn't prevent the others from working.
    
    // Logic for path resolution in packaged mode:
    const appRoot = app.isPackaged ? app.getAppPath() : path.join(__dirname, '..');
    
    // For native modules in packaged mode, use the unpacked path
    if (app.isPackaged) {
      const unpackedPath = appRoot.replace('app.asar', 'app.asar.unpacked');
      log(`ASAR Unpacked path: ${unpackedPath}`);
      
      // Add the unpacked node_modules to the module search path
      // This ensures native addons like better-sqlite3 are found outside ASAR
      const unpackedNodeModules = path.join(unpackedPath, 'node_modules');
      if (fs.existsSync(unpackedNodeModules)) {
        require('module').globalPaths.unshift(unpackedNodeModules);
        log(`Added unpacked node_modules to search path: ${unpackedNodeModules}`);
      }
    }
    
    // Override console for backend logging
    console.log = (...args) => {
        log(`[BACKEND] ${args.join(' ')}`);
    };
    console.error = (...args) => {
        log(`[ERR] ${args.join(' ')}`);
        originalConsoleError(...args);
    };

    // ─── Load Backend Server (Express API) ───
    let serverLoaded = false;
    try {
      const serverPath = path.join(appRoot, 'backend', 'server', 'index.js');
      log(`Loading server from: ${serverPath}`);
      require(serverPath);
      serverLoaded = true;
      log('Backend API server loaded successfully.');
    } catch (e) {
      log(`BACKEND SERVER FAIL: ${e.message}`);
      log(`Stack: ${e.stack}`);
    }

    // ─── Load Polling Service (Background Scans) ───
    try {
      const pollingPath = path.join(appRoot, 'backend', 'services', 'polling.js');
      log(`Loading polling service from: ${pollingPath}`);
      require(pollingPath);
      log('Polling service loaded successfully.');
    } catch (e) {
      log(`POLLING SERVICE FAIL (non-fatal): ${e.message}`);
      // Polling is optional — the app can work without background scans
    }

    if (!serverLoaded) {
      log('WARNING: Backend server failed to load. UI will show error state.');
      const { dialog } = require('electron');
      dialog.showErrorBox(
        'Sentinel Backend Error',
        `The backend server could not start.\n\nCheck: ${logPath}\n\nThe app will still open but features may be limited.`
      );
    }

    // Wait for the backend server to be ready before showing the window
    await new Promise((resolve) => {
      let attempts = 0;
      const check = () => {
        const req = require('http').get('http://127.0.0.1:3001/api/system/stats', (res) => {
          log("Health check: Backend responded (OK)");
          resolve();
        });
        req.on('error', (err) => {
          attempts++;
          if (attempts % 5 === 0) log(`Health check attempt ${attempts} failed: ${err.message}`);
          if (attempts < 20) setTimeout(check, 250);
          else {
            log("Health check: Giving up after 20 attempts.");
            resolve();
          }
        });
        req.end();
      };
      check();
    });

    createWindow();

    // IPC Handlers for React Frontend (accessed via window.sentinel.*)
    ipcMain.on('app-quit', () => {
      app.quit();
    });

    ipcMain.handle('clear-memory', async () => {
      const wins = BrowserWindow.getAllWindows();
      for (const win of wins) {
        await win.webContents.session.clearCache();
        await win.webContents.session.clearStorageData({
          storages: ['appcache', 'cookies', 'filesystem', 'indexdb', 'localstorage', 'shadercache', 'websql', 'serviceworkers', 'cachestorage']
        });
      }
      return { success: true, message: 'Memory and cache cleared successfully' };
    });

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
