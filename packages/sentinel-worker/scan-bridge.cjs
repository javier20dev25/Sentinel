/**
 * CJS Bridge: This file runs in CommonJS mode (.cjs extension) 
 * so the scanner's require() calls work correctly.
 * The ESM worker imports this via createRequire.
 */
'use strict';

const Scanner = require('./core/scanner/index.js');

module.exports = {
  async scanDirectory(dirPath, repoHash, depth, options) {
    return Scanner.scanDirectory(dirPath, repoHash, depth, options);
  }
};
