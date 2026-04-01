/**
 * Sentinel: Electron Main Process (HARDENED)
 * 
 * SECURITY: contextIsolation enabled, nodeIntegration disabled.
 * Renderer process cannot access Node.js APIs directly.
 * All IPC communication goes through the preload.js bridge.
 * 
 * Audit: VULN-002 remediated — Electron security best practices applied.
 */

'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

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
      const indexPath = path.join(__dirname, '../dist/index.html');
      console.log(`🛡️ Loading UI from: ${indexPath}`);
      mainWindow.loadFile(indexPath).catch(err => {
        console.error("❌ Failed to load index.html:", err);
      });
      // TEMPORARY: Open DevTools in production to debug black screen
      mainWindow.webContents.openDevTools();
    }

    // Debugging support
    mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
      console.error(`❌ UI Failed to load: ${errorCode} - ${errorDescription} (${validatedURL})`);
    });
  }

  app.whenReady().then(async () => {
    // Initialize backend services AFTER app is ready (avoids SQLite ABI issues)
    console.log("🛡️ Initializing Sentinel Backend...");
    try {
      require('../backend/server/index.js');
      require('../backend/services/polling.js');
      console.log("✅ Sentinel backend running.");
    } catch (e) {
      console.error("❌ Backend failed to start:", e.message);
    }

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
