/**
 * Sentinel: Electron Preload Script (SECURITY BRIDGE)
 * 
 * This script runs in a sandboxed context between the renderer (web page)
 * and the main Electron process. It exposes ONLY the specific APIs that
 * the frontend needs, preventing direct access to Node.js APIs.
 * 
 * SECURITY: contextBridge.exposeInMainWorld creates a frozen, non-tamperable
 * API surface. The renderer cannot access require(), fs, child_process, etc.
 * 
 * Audit: VULN-002 remediated — contextIsolation enabled with minimal bridge.
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {
  /**
   * Request the app to quit.
   * Maps to: ipcMain.on('app-quit', ...)
   */
  quit: () => ipcRenderer.send('app-quit'),

  /**
   * Clear all browser cache and storage.
   * Maps to: ipcMain.handle('clear-memory', ...)
   * Returns: Promise<{ success: boolean, message: string }>
   */
  clearMemory: () => ipcRenderer.invoke('clear-memory'),

  /**
   * Get the platform identifier.
   * Useful for OS-specific behavior in the renderer.
   */
  platform: process.platform,

  /**
   * Get the app version.
   */
  version: process.env.npm_package_version || '1.0.0'
});
