/**
 * Sentinel: Global Hardener Bridge
 * Manages global security switches and cross-origin policies.
 */

'use strict';

const db = require('./db');

class HardenerBridge {
    /**
     * Gets the status of global security switches.
     */
    getSwitchesStatus() {
        try {
            const npmIgnoreScripts = db.getSystemConfig('global_npm_ignore_scripts') === 'true';
            const autoHardenEnabled = db.getSystemConfig('global_auto_harden') === 'true';
            
            return {
                npmIgnoreScripts,
                autoHardenEnabled
            };
        } catch (e) {
            return { npmIgnoreScripts: false, autoHardenEnabled: false };
        }
    }

    /**
     * Sets the global npm ignore-scripts flag.
     */
    setNpmIgnoreScripts(active) {
        try {
            db.setSystemConfig('global_npm_ignore_scripts', active ? 'true' : 'false');
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    /**
     * Toggles global auto-harden feature.
     */
    setAutoHarden(active) {
        try {
            db.setSystemConfig('global_auto_harden', active ? 'true' : 'false');
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }
}

module.exports = new HardenerBridge();
