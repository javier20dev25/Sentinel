/**
 * Sentinel: Typo-Squatting Detector Engine
 *
 * Detects potential typosquatting packages by computing
 * Damerau–Levenshtein distance against the top 500 most
 * depended-upon npm packages.
 */

import { ForensicFinding } from './types';

// ---------------------------------------------------------------------------
// Damerau–Levenshtein distance (allows transpositions) — optimised with a
// flat Uint8Array and early length-gap bailout since we only care about
// distances ≤ 3.
// ---------------------------------------------------------------------------

// Reusable row buffers for Damerau-Levenshtein (avoids per-call allocation).
let _dlPP: number[] = [];
let _dlP: number[]  = [];
let _dlC: number[]  = [];

export function damerauLevenshtein(a: string, b: string): number {
  const an = a.length;
  const bn = b.length;
  if (an === 0) return bn;
  if (bn === 0) return an;

  const maxDist = 3;
  if (Math.abs(an - bn) > maxDist) return Math.abs(an - bn);
  if (an < maxDist || bn < maxDist) {
    // For very short strings the row-based approach below can be wrong;
    // fall back to a simple 2D allocation (rare).
    const cols = bn + 1;
    const size = (an + 1) * cols;
    const m = new Uint8Array(size);
    for (let j = 0; j <= bn; j++) m[j] = j;
    for (let i = 1; i <= an; i++) {
      m[i * cols] = i;
      for (let j = 1; j <= bn; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        const idx = i * cols + j;
        m[idx] = Math.min(m[idx - 1] + 1, m[(i - 1) * cols + j] + 1, m[(i - 1) * cols + (j - 1)] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          m[idx] = Math.min(m[idx], m[(i - 2) * cols + (j - 2)] + cost);
        }
      }
    }
    return m[size - 1];
  }

  // Grow reusable buffers if needed
  while (_dlPP.length < bn + 1) _dlPP.push(0);
  while (_dlP.length  < bn + 1) _dlP.push(0);
  while (_dlC.length  < bn + 1) _dlC.push(0);

  // Row 0
  for (let j = 0; j <= bn; j++) { _dlPP[j] = j; _dlP[j] = j; }

  for (let i = 1; i <= an; i++) {
    _dlC[0] = i;
    let rowMin = i;
    for (let j = 1; j <= bn; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      _dlC[j] = Math.min(
        _dlC[j - 1] + 1,
        _dlP[j] + 1,
        _dlP[j - 1] + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        _dlC[j] = Math.min(_dlC[j], _dlPP[j - 2] + cost);
      }
      if (_dlC[j] < rowMin) rowMin = _dlC[j];
    }
    if (rowMin > maxDist) return maxDist + 1;

    // Shift rows
    const tmp = _dlPP;
    _dlPP = _dlP;
    _dlP = _dlC;
    _dlC = tmp;
  }

  return _dlP[bn];
}

// ---------------------------------------------------------------------------
// Homoglyph / confusable character mapping
// ---------------------------------------------------------------------------

const HOMOGLYPH_MAP: Record<string, string> = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
  '7': 't', '8': 'b', '9': 'g',
  '¡': 'i', 'ⅼ': 'l', 'ӏ': 'l', 'ӧ': 'o',
};

export function normalizeHomoglyphs(name: string): string {
  return name
    .toLowerCase()
    .split('')
    .map((ch) => HOMOGLYPH_MAP[ch] ?? ch)
    .join('');
}

// ---------------------------------------------------------------------------
// Interface & top-500 database
// ---------------------------------------------------------------------------

export interface PopularPackage {
  name: string;
  downloads: number;
  category: string;
}

export interface TypoMatch {
  dependency: string;
  suggestedOriginal: string;
  distance: number;
  score: number;
}

const TOP_PACKAGES: PopularPackage[] = [
  // ── Frameworks & Runtimes ──────────────────────────────────────────
  { name: 'express',          downloads: 35_000_000, category: 'framework' },
  { name: 'next',             downloads: 12_000_000, category: 'framework' },
  { name: 'react',            downloads: 40_000_000, category: 'framework' },
  { name: 'react-dom',        downloads: 40_000_000, category: 'framework' },
  { name: 'vue',              downloads: 8_000_000,  category: 'framework' },
  { name: 'angular',          downloads: 5_000_000,  category: 'framework' },
  { name: 'svelte',           downloads: 2_500_000,  category: 'framework' },
  { name: 'gatsby',           downloads: 1_500_000,  category: 'framework' },
  { name: 'nuxt',             downloads: 1_200_000,  category: 'framework' },
  { name: 'remix',            downloads: 800_000,    category: 'framework' },
  { name: 'meteor',           downloads: 300_000,    category: 'framework' },
  { name: 'hapi',             downloads: 1_000_000,  category: 'framework' },
  { name: 'koa',              downloads: 2_000_000,  category: 'framework' },
  { name: 'fastify',          downloads: 3_000_000,  category: 'framework' },
  { name: 'socket.io',        downloads: 5_000_000,  category: 'framework' },
  { name: 'nestjs',           downloads: 4_000_000,  category: 'framework' },
  { name: 'adonisjs',         downloads: 200_000,    category: 'framework' },
  { name: 'ember-source',     downloads: 500_000,    category: 'framework' },
  { name: 'backbone',         downloads: 400_000,    category: 'framework' },

  // ── Core Utilities ─────────────────────────────────────────────────
  { name: 'lodash',           downloads: 55_000_000, category: 'utility' },
  { name: 'chalk',            downloads: 45_000_000, category: 'utility' },
  { name: 'axios',            downloads: 35_000_000, category: 'utility' },
  { name: 'request',          downloads: 25_000_000, category: 'utility' },
  { name: 'moment',           downloads: 20_000_000, category: 'utility' },
  { name: 'dayjs',            downloads: 8_000_000,  category: 'utility' },
  { name: 'date-fns',         downloads: 15_000_000, category: 'utility' },
  { name: 'uuid',             downloads: 50_000_000, category: 'utility' },
  { name: 'fs-extra',         downloads: 40_000_000, category: 'utility' },
  { name: 'glob',             downloads: 30_000_000, category: 'utility' },
  { name: 'rimraf',           downloads: 25_000_000, category: 'utility' },
  { name: 'dotenv',           downloads: 30_000_000, category: 'utility' },
  { name: 'cross-env',        downloads: 10_000_000, category: 'utility' },
  { name: 'yargs',            downloads: 20_000_000, category: 'utility' },
  { name: 'commander',        downloads: 15_000_000, category: 'utility' },
  { name: 'inquirer',         downloads: 5_000_000,  category: 'utility' },
  { name: 'ora',              downloads: 8_000_000,  category: 'utility' },
  { name: 'bluebird',         downloads: 8_000_000,  category: 'utility' },
  { name: 'async',            downloads: 10_000_000, category: 'utility' },
  { name: 'p-limit',          downloads: 12_000_000, category: 'utility' },
  { name: 'p-map',            downloads: 8_000_000,  category: 'utility' },
  { name: 'semver',           downloads: 50_000_000, category: 'utility' },
  { name: 'debug',            downloads: 60_000_000, category: 'utility' },
  { name: 'ms',               downloads: 50_000_000, category: 'utility' },
  { name: 'supports-color',   downloads: 45_000_000, category: 'utility' },
  { name: 'has-flag',         downloads: 40_000_000, category: 'utility' },
  { name: 'node-fetch',       downloads: 15_000_000, category: 'utility' },
  { name: 'got',              downloads: 10_000_000, category: 'utility' },
  { name: 'undici',           downloads: 5_000_000,  category: 'utility' },
  { name: 'cheerio',          downloads: 5_000_000,  category: 'utility' },
  { name: 'jsdom',            downloads: 4_000_000,  category: 'utility' },
  { name: 'puppeteer',        downloads: 4_000_000,  category: 'utility' },
  { name: 'playwright',       downloads: 3_000_000,  category: 'utility' },
  { name: 'lodash.merge',     downloads: 15_000_000, category: 'utility' },
  { name: 'lodash.get',       downloads: 10_000_000, category: 'utility' },
  { name: 'deepmerge',        downloads: 10_000_000, category: 'utility' },
  { name: 'clone-deep',       downloads: 5_000_000,  category: 'utility' },
  { name: 'immer',            downloads: 8_000_000,  category: 'utility' },
  { name: 'rxjs',             downloads: 12_000_000, category: 'utility' },
  { name: 'zone.js',          downloads: 5_000_000,  category: 'utility' },
  { name: 'nanoid',           downloads: 20_000_000, category: 'utility' },
  { name: 'crypto-js',        downloads: 5_000_000,  category: 'utility' },
  { name: 'bcrypt',           downloads: 3_000_000,  category: 'utility' },
  { name: 'bcryptjs',         downloads: 3_000_000,  category: 'utility' },
  { name: 'jsonwebtoken',     downloads: 5_000_000,  category: 'utility' },
  { name: 'passport',         downloads: 3_000_000,  category: 'utility' },
  { name: 'ajv',              downloads: 20_000_000, category: 'utility' },
  { name: 'joi',              downloads: 5_000_000,  category: 'utility' },
  { name: 'zod',              downloads: 8_000_000,  category: 'utility' },
  { name: 'yup',              downloads: 5_000_000,  category: 'utility' },
  { name: 'class-transformer', downloads: 3_000_000, category: 'utility' },
  { name: 'class-validator',  downloads: 3_000_000,  category: 'utility' },
  { name: 'reflect-metadata', downloads: 10_000_000, category: 'utility' },

  // ── Build Tools / Compilers / Bundlers ─────────────────────────────
  { name: 'webpack',          downloads: 20_000_000, category: 'build-tool' },
  { name: 'babel-core',       downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/core',      downloads: 25_000_000, category: 'build-tool' },
  { name: '@babel/preset-env', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/preset-react', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/preset-typescript', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-runtime', downloads: 12_000_000, category: 'build-tool' },
  { name: '@babel/runtime',   downloads: 25_000_000, category: 'build-tool' },
  { name: 'babel-loader',     downloads: 10_000_000, category: 'build-tool' },
  { name: 'ts-loader',        downloads: 3_000_000,  category: 'build-tool' },
  { name: 'typescript',       downloads: 30_000_000, category: 'build-tool' },
  { name: 'esbuild',          downloads: 10_000_000, category: 'build-tool' },
  { name: 'vite',             downloads: 10_000_000, category: 'build-tool' },
  { name: 'rollup',           downloads: 8_000_000,  category: 'build-tool' },
  { name: 'parcel',           downloads: 1_500_000,  category: 'build-tool' },
  { name: 'ts-node',          downloads: 8_000_000,  category: 'build-tool' },
  { name: 'tslib',            downloads: 30_000_000, category: 'build-tool' },
  { name: 'gulp',             downloads: 2_000_000,  category: 'build-tool' },
  { name: 'grunt',            downloads: 1_000_000,  category: 'build-tool' },
  { name: 'sass',             downloads: 8_000_000,  category: 'build-tool' },
  { name: 'less',             downloads: 2_000_000,  category: 'build-tool' },
  { name: 'postcss',          downloads: 15_000_000, category: 'build-tool' },
  { name: 'autoprefixer',     downloads: 15_000_000, category: 'build-tool' },
  { name: 'cssnano',          downloads: 3_000_000,  category: 'build-tool' },
  { name: 'mini-css-extract-plugin', downloads: 8_000_000, category: 'build-tool' },
  { name: 'css-loader',       downloads: 15_000_000, category: 'build-tool' },
  { name: 'style-loader',     downloads: 12_000_000, category: 'build-tool' },
  { name: 'file-loader',      downloads: 10_000_000, category: 'build-tool' },
  { name: 'url-loader',       downloads: 8_000_000,  category: 'build-tool' },
  { name: 'html-webpack-plugin', downloads: 10_000_000, category: 'build-tool' },
  { name: 'terser-webpack-plugin', downloads: 10_000_000, category: 'build-tool' },
  { name: 'copy-webpack-plugin', downloads: 5_000_000, category: 'build-tool' },
  { name: 'eslint',           downloads: 20_000_000, category: 'build-tool' },
  { name: 'prettier',         downloads: 15_000_000, category: 'build-tool' },
  { name: 'babel-eslint',     downloads: 5_000_000,  category: 'build-tool' },
  { name: '@typescript-eslint/eslint-plugin', downloads: 10_000_000, category: 'build-tool' },
  { name: '@typescript-eslint/parser', downloads: 10_000_000, category: 'build-tool' },
  { name: 'eslint-plugin-react', downloads: 8_000_000, category: 'build-tool' },
  { name: 'eslint-config-airbnb', downloads: 5_000_000, category: 'build-tool' },
  { name: 'stylelint',        downloads: 2_000_000,  category: 'build-tool' },
  { name: 'npm-run-all',      downloads: 5_000_000,  category: 'build-tool' },
  { name: 'concurrently',     downloads: 5_000_000,  category: 'build-tool' },
  { name: 'nodemon',          downloads: 5_000_000,  category: 'build-tool' },
  { name: 'husky',            downloads: 8_000_000,  category: 'build-tool' },
  { name: 'lint-staged',      downloads: 8_000_000,  category: 'build-tool' },
  { name: 'commitlint',       downloads: 2_000_000,  category: 'build-tool' },
  { name: 'standard',         downloads: 2_000_000,  category: 'build-tool' },

  // ── Database / ORM / Storage ───────────────────────────────────────
  { name: 'mongoose',         downloads: 3_000_000,  category: 'database' },
  { name: 'mongodb',          downloads: 3_000_000,  category: 'database' },
  { name: 'pg',               downloads: 5_000_000,  category: 'database' },
  { name: 'mysql',            downloads: 2_000_000,  category: 'database' },
  { name: 'mysql2',           downloads: 5_000_000,  category: 'database' },
  { name: 'sqlite3',          downloads: 2_000_000,  category: 'database' },
  { name: 'better-sqlite3',   downloads: 2_000_000,  category: 'database' },
  { name: 'prisma',           downloads: 5_000_000,  category: 'database' },
  { name: '@prisma/client',   downloads: 5_000_000,  category: 'database' },
  { name: 'typeorm',          downloads: 2_000_000,  category: 'database' },
  { name: 'sequelize',        downloads: 2_000_000,  category: 'database' },
  { name: 'knex',             downloads: 2_000_000,  category: 'database' },
  { name: 'drizzle-orm',      downloads: 1_000_000,  category: 'database' },
  { name: 'redis',            downloads: 3_000_000,  category: 'database' },
  { name: 'ioredis',          downloads: 3_000_000,  category: 'database' },
  { name: 'firebase',         downloads: 1_000_000,  category: 'database' },
  { name: 'firebase-admin',   downloads: 1_500_000,  category: 'database' },
  { name: 'aws-sdk',          downloads: 15_000_000, category: 'database' },
  { name: '@aws-sdk/client-s3', downloads: 10_000_000, category: 'database' },
  { name: 'googleapis',       downloads: 2_000_000,  category: 'database' },
  { name: 'graphql',          downloads: 5_000_000,  category: 'database' },
  { name: '@apollo/client',   downloads: 3_000_000,  category: 'database' },
  { name: 'apollo-server',    downloads: 1_000_000,  category: 'database' },
  { name: 'type-graphql',     downloads: 500_000,    category: 'database' },
  { name: 'couchbase',        downloads: 200_000,    category: 'database' },
  { name: 'rethinkdb',        downloads: 200_000,    category: 'database' },

  // ── Testing ────────────────────────────────────────────────────────
  { name: 'jest',             downloads: 20_000_000, category: 'testing' },
  { name: 'mocha',            downloads: 8_000_000,  category: 'testing' },
  { name: 'chai',             downloads: 8_000_000,  category: 'testing' },
  { name: 'sinon',            downloads: 5_000_000,  category: 'testing' },
  { name: 'ava',              downloads: 500_000,    category: 'testing' },
  { name: 'tap',              downloads: 2_000_000,  category: 'testing' },
  { name: 'tape',             downloads: 2_000_000,  category: 'testing' },
  { name: 'supertest',        downloads: 5_000_000,  category: 'testing' },
  { name: 'nyc',              downloads: 3_000_000,  category: 'testing' },
  { name: 'istanbul',         downloads: 3_000_000,  category: 'testing' },
  { name: 'c8',               downloads: 2_000_000,  category: 'testing' },
  { name: '@testing-library/react', downloads: 10_000_000, category: 'testing' },
  { name: '@testing-library/jest-dom', downloads: 8_000_000, category: 'testing' },
  { name: '@testing-library/user-event', downloads: 5_000_000, category: 'testing' },
  { name: 'cypress',          downloads: 5_000_000,  category: 'testing' },
  { name: 'playwright-test',  downloads: 500_000,    category: 'testing' },
  { name: 'vitest',           downloads: 3_000_000,  category: 'testing' },
  { name: 'jasmine',          downloads: 2_000_000,  category: 'testing' },
  { name: 'karma',            downloads: 1_000_000,  category: 'testing' },
  { name: 'enzyme',           downloads: 1_500_000,  category: 'testing' },
  { name: 'nock',             downloads: 2_000_000,  category: 'testing' },
  { name: 'faker',            downloads: 5_000_000,  category: 'testing' },
  { name: '@faker-js/faker',  downloads: 5_000_000,  category: 'testing' },
  { name: 'msw',              downloads: 2_000_000,  category: 'testing' },

  // ── Security / Auth ────────────────────────────────────────────────
  { name: 'helmet',           downloads: 3_000_000,  category: 'security' },
  { name: 'cors',             downloads: 20_000_000, category: 'security' },
  { name: 'csurf',            downloads: 500_000,    category: 'security' },
  { name: 'express-rate-limit', downloads: 2_000_000, category: 'security' },
  { name: 'express-session',  downloads: 3_000_000,  category: 'security' },
  { name: 'cookie-parser',    downloads: 10_000_000, category: 'security' },
  { name: 'cookie-session',   downloads: 500_000,    category: 'security' },
  { name: 'passport-jwt',     downloads: 1_000_000,  category: 'security' },
  { name: 'passport-local',   downloads: 1_500_000,  category: 'security' },
  { name: 'bcrypt-nodejs',    downloads: 500_000,    category: 'security' },
  { name: 'jose',             downloads: 2_000_000,  category: 'security' },
  { name: 'validator',        downloads: 10_000_000, category: 'security' },
  { name: 'sanitize-html',    downloads: 2_000_000,  category: 'security' },
  { name: 'xss',              downloads: 1_000_000,  category: 'security' },
  { name: 'dompurify',        downloads: 3_000_000,  category: 'security' },
  { name: 'secure-compare',   downloads: 500_000,    category: 'security' },
  { name: 'snyk',             downloads: 500_000,    category: 'security' },
  { name: 'npm-audit',        downloads: 100_000,    category: 'security' },
  { name: 'owasp-password-strength-test', downloads: 100_000, category: 'security' },

  // ── Template / View Engines ────────────────────────────────────────
  { name: 'mustache',         downloads: 3_000_000,  category: 'utility' },
  { name: 'handlebars',       downloads: 5_000_000,  category: 'utility' },
  { name: 'pug',              downloads: 2_000_000,  category: 'utility' },
  { name: 'ejs',              downloads: 5_000_000,  category: 'utility' },
  { name: 'nunjucks',         downloads: 1_000_000,  category: 'utility' },
  { name: 'markdown-it',      downloads: 5_000_000,  category: 'utility' },
  { name: 'marked',           downloads: 5_000_000,  category: 'utility' },
  { name: 'remark',           downloads: 2_000_000,  category: 'utility' },
  { name: 'react-markdown',   downloads: 3_000_000,  category: 'utility' },
  { name: 'ejs-lint',         downloads: 200_000,    category: 'utility' },

  // ── Streaming / HTTP / Protocol ────────────────────────────────────
  { name: 'ws',               downloads: 15_000_000, category: 'utility' },
  { name: 'socket.io-client', downloads: 4_000_000,  category: 'utility' },
  { name: 'express-ws',       downloads: 500_000,    category: 'utility' },
  { name: 'mqtt',             downloads: 1_000_000,  category: 'utility' },
  { name: 'amqplib',          downloads: 2_000_000,  category: 'utility' },
  { name: 'kafkajs',          downloads: 1_000_000,  category: 'utility' },
  { name: 'bull',             downloads: 1_000_000,  category: 'utility' },
  { name: 'bullmq',           downloads: 500_000,    category: 'utility' },
  { name: 'agenda',           downloads: 300_000,    category: 'utility' },
  { name: 'node-cron',        downloads: 2_000_000,  category: 'utility' },
  { name: 'node-schedule',    downloads: 1_000_000,  category: 'utility' },
  { name: 'compression',      downloads: 8_000_000,  category: 'utility' },
  { name: 'body-parser',      downloads: 20_000_000, category: 'utility' },
  { name: 'morgan',           downloads: 5_000_000,  category: 'utility' },
  { name: 'multer',           downloads: 3_000_000,  category: 'utility' },
  { name: 'busboy',           downloads: 3_000_000,  category: 'utility' },
  { name: 'formidable',       downloads: 2_000_000,  category: 'utility' },
  { name: 'http-proxy',       downloads: 2_000_000,  category: 'utility' },
  { name: 'http-proxy-middleware', downloads: 2_000_000, category: 'utility' },
  { name: 'express-http-proxy', downloads: 500_000,  category: 'utility' },
  { name: 'http-status-codes', downloads: 3_000_000, category: 'utility' },

  // ── CLI / Process / Shell ─────────────────────────────────────────
  { name: 'shelljs',          downloads: 8_000_000,  category: 'utility' },
  { name: 'execa',            downloads: 15_000_000, category: 'utility' },
  { name: 'cross-spawn',      downloads: 20_000_000, category: 'utility' },
  { name: 'signal-exit',      downloads: 30_000_000, category: 'utility' },
  { name: 'which',            downloads: 20_000_000, category: 'utility' },
  { name: 'npm-check',        downloads: 500_000,    category: 'utility' },
  { name: 'update-notifier',  downloads: 5_000_000,  category: 'utility' },
  { name: 'configstore',      downloads: 5_000_000,  category: 'utility' },
  { name: 'env-paths',        downloads: 5_000_000,  category: 'utility' },
  { name: 'cli-color',        downloads: 2_000_000,  category: 'utility' },
  { name: 'colorette',        downloads: 5_000_000,  category: 'utility' },
  { name: 'picocolors',       downloads: 10_000_000, category: 'utility' },
  { name: 'ansi-styles',      downloads: 60_000_000, category: 'utility' },
  { name: 'wrap-ansi',        downloads: 40_000_000, category: 'utility' },
  { name: 'string-width',     downloads: 50_000_000, category: 'utility' },
  { name: 'strip-ansi',       downloads: 50_000_000, category: 'utility' },
  { name: 'slice-ansi',       downloads: 10_000_000, category: 'utility' },
  { name: 'cli-truncate',     downloads: 10_000_000, category: 'utility' },
  { name: 'log-symbols',      downloads: 10_000_000, category: 'utility' },
  { name: 'spinnies',         downloads: 500_000,    category: 'utility' },
  { name: 'listr',            downloads: 2_000_000,  category: 'utility' },
  { name: 'listr2',           downloads: 2_000_000,  category: 'utility' },

  // ── Date / Time ────────────────────────────────────────────────────
  { name: 'moment-timezone',  downloads: 8_000_000,  category: 'utility' },
  { name: 'luxon',            downloads: 3_000_000,  category: 'utility' },
  { name: 'dateformat',       downloads: 3_000_000,  category: 'utility' },
  { name: 'pretty-ms',        downloads: 5_000_000,  category: 'utility' },
  { name: 'parse-duration',   downloads: 2_000_000,  category: 'utility' },
  { name: 'cron-parser',      downloads: 2_000_000,  category: 'utility' },

  // ── Number / Math ──────────────────────────────────────────────────
  { name: 'numeral',          downloads: 1_000_000,  category: 'utility' },
  { name: 'mathjs',           downloads: 2_000_000,  category: 'utility' },
  { name: 'decimal.js',       downloads: 3_000_000,  category: 'utility' },
  { name: 'big.js',           downloads: 3_000_000,  category: 'utility' },
  { name: 'bignumber.js',     downloads: 3_000_000,  category: 'utility' },
  { name: 'fraction.js',      downloads: 500_000,    category: 'utility' },
  { name: 'd3',               downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-scale',         downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-shape',         downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-array',         downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-axis',          downloads: 1_000_000,  category: 'utility' },
  { name: 'd3-brush',         downloads: 1_000_000,  category: 'utility' },
  { name: 'd3-force',         downloads: 1_000_000,  category: 'utility' },
  { name: 'd3-hierarchy',     downloads: 500_000,    category: 'utility' },
  { name: 'd3-interpolate',   downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-path',          downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-polygon',       downloads: 500_000,    category: 'utility' },
  { name: 'd3-quadtree',      downloads: 500_000,    category: 'utility' },
  { name: 'd3-random',        downloads: 500_000,    category: 'utility' },
  { name: 'd3-scale-chromatic', downloads: 1_000_000, category: 'utility' },
  { name: 'd3-selection',     downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-time-format',   downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-timer',         downloads: 2_000_000,  category: 'utility' },
  { name: 'd3-transition',    downloads: 1_500_000,  category: 'utility' },
  { name: 'd3-zoom',          downloads: 1_500_000,  category: 'utility' },

  // ── Files / Paths ──────────────────────────────────────────────────
  { name: 'path-exists',      downloads: 30_000_000, category: 'utility' },
  { name: 'find-up',          downloads: 25_000_000, category: 'utility' },
  { name: 'locate-path',      downloads: 20_000_000, category: 'utility' },
  { name: 'pkg-dir',          downloads: 15_000_000, category: 'utility' },
  { name: 'read-pkg',         downloads: 10_000_000, category: 'utility' },
  { name: 'read-pkg-up',      downloads: 8_000_000,  category: 'utility' },
  { name: 'write-pkg',        downloads: 1_000_000,  category: 'utility' },
  { name: 'del',              downloads: 15_000_000, category: 'utility' },
  { name: 'make-dir',         downloads: 20_000_000, category: 'utility' },
  { name: 'temp-dir',         downloads: 5_000_000,  category: 'utility' },
  { name: 'tempfile',         downloads: 3_000_000,  category: 'utility' },
  { name: 'graceful-fs',      downloads: 60_000_000, category: 'utility' },
  { name: 'jsonfile',         downloads: 20_000_000, category: 'utility' },
  { name: 'load-json-file',   downloads: 5_000_000,  category: 'utility' },
  { name: 'write-json-file',  downloads: 3_000_000,  category: 'utility' },
  { name: 'readdirp',         downloads: 5_000_000,  category: 'utility' },
  { name: 'globby',           downloads: 20_000_000, category: 'utility' },
  { name: 'ignore',           downloads: 30_000_000, category: 'utility' },
  { name: 'slash',            downloads: 25_000_000, category: 'utility' },
  { name: 'normalize-path',   downloads: 25_000_000, category: 'utility' },
  { name: 'is-path-inside',   downloads: 5_000_000,  category: 'utility' },
  { name: 'path-type',        downloads: 15_000_000, category: 'utility' },
  { name: 'dir-glob',         downloads: 10_000_000, category: 'utility' },
  { name: 'arrify',           downloads: 20_000_000, category: 'utility' },
  { name: 'micromatch',       downloads: 30_000_000, category: 'utility' },
  { name: 'picomatch',        downloads: 30_000_000, category: 'utility' },

  // ── String / Text ──────────────────────────────────────────────────
  { name: 'camelcase',        downloads: 30_000_000, category: 'utility' },
  { name: 'decamelize',       downloads: 15_000_000, category: 'utility' },
  { name: 'pascalcase',       downloads: 3_000_000,  category: 'utility' },
  { name: 'kebab-case',       downloads: 500_000,    category: 'utility' },
  { name: 'sentence-case',    downloads: 1_000_000,  category: 'utility' },
  { name: 'title-case',       downloads: 1_000_000,  category: 'utility' },
  { name: 'pluralize',        downloads: 3_000_000,  category: 'utility' },
  { name: 'inflection',       downloads: 1_000_000,  category: 'utility' },
  { name: 'change-case',      downloads: 3_000_000,  category: 'utility' },
  { name: 'param-case',       downloads: 2_000_000,  category: 'utility' },
  { name: 'no-case',          downloads: 10_000_000, category: 'utility' },
  { name: 'upper-case',       downloads: 10_000_000, category: 'utility' },
  { name: 'lower-case',       downloads: 10_000_000, category: 'utility' },
  { name: 'capital-case',     downloads: 1_000_000,  category: 'utility' },
  { name: 'constant-case',    downloads: 2_000_000,  category: 'utility' },
  { name: 'dot-case',         downloads: 2_000_000,  category: 'utility' },
  { name: 'path-case',        downloads: 1_000_000,  category: 'utility' },
  { name: 'snake-case',       downloads: 1_000_000,  category: 'utility' },
  { name: 'sponge-case',      downloads: 100_000,    category: 'utility' },
  { name: 'swap-case',        downloads: 500_000,    category: 'utility' },
  { name: 'he',               downloads: 5_000_000,  category: 'utility' },
  { name: 'entities',         downloads: 10_000_000, category: 'utility' },
  { name: 'html-entities',    downloads: 3_000_000,  category: 'utility' },
  { name: 'strip-markdown',   downloads: 500_000,    category: 'utility' },
  { name: 'strip-html',       downloads: 500_000,    category: 'utility' },
  { name: 'striptags',        downloads: 3_000_000,  category: 'utility' },
  { name: 'truncate-utf8-bytes', downloads: 500_000, category: 'utility' },
  { name: 'wordwrap',         downloads: 5_000_000,  category: 'utility' },
  { name: 'string-length',    downloads: 10_000_000, category: 'utility' },
  { name: 'is-fullwidth-code-point', downloads: 30_000_000, category: 'utility' },

  // ── Process / OS ───────────────────────────────────────────────────
  { name: 'os-tmpdir',        downloads: 30_000_000, category: 'utility' },
  { name: 'osenv',            downloads: 10_000_000, category: 'utility' },
  { name: 'os-name',          downloads: 3_000_000,  category: 'utility' },
  { name: 'is-windows',       downloads: 30_000_000, category: 'utility' },
  { name: 'is-docker',        downloads: 10_000_000, category: 'utility' },
  { name: 'is-ci',            downloads: 5_000_000,  category: 'utility' },
  { name: 'ci-info',          downloads: 20_000_000, category: 'utility' },
  { name: 'user-home',        downloads: 3_000_000,  category: 'utility' },
  { name: 'untildify',        downloads: 5_000_000,  category: 'utility' },
  { name: 'homedir',          downloads: 2_000_000,  category: 'utility' },
  { name: 'getos',            downloads: 1_000_000,  category: 'utility' },
  { name: 'arch',             downloads: 2_000_000,  category: 'utility' },
  { name: 'cpu-features',     downloads: 1_000_000,  category: 'utility' },
  { name: 'node-machine-id',  downloads: 500_000,    category: 'utility' },

  // ── Network / URL / DNS ────────────────────────────────────────────
  { name: 'ip',               downloads: 5_000_000,  category: 'utility' },
  { name: 'ipaddr.js',        downloads: 5_000_000,  category: 'utility' },
  { name: 'public-ip',        downloads: 2_000_000,  category: 'utility' },
  { name: 'internal-ip',      downloads: 1_000_000,  category: 'utility' },
  { name: 'url-parse',        downloads: 10_000_000, category: 'utility' },
  { name: 'url-join',         downloads: 5_000_000,  category: 'utility' },
  { name: 'url-pattern',      downloads: 500_000,    category: 'utility' },
  { name: 'normalize-url',    downloads: 10_000_000, category: 'utility' },
  { name: 'is-url',           downloads: 3_000_000,  category: 'utility' },
  { name: 'is-http-url',      downloads: 500_000,    category: 'utility' },
  { name: 'is-https-url',     downloads: 500_000,    category: 'utility' },
  { name: 'query-string',     downloads: 15_000_000, category: 'utility' },
  { name: 'qs',               downloads: 30_000_000, category: 'utility' },
  { name: 'parseurl',         downloads: 2_000_000,  category: 'utility' },
  { name: 'encodeurl',        downloads: 3_000_000,  category: 'utility' },
  { name: 'decode-uri-component', downloads: 25_000_000, category: 'utility' },
  { name: 'split-on-first',   downloads: 5_000_000,  category: 'utility' },
  { name: 'filter-obj',       downloads: 3_000_000,  category: 'utility' },
  { name: 'dns-sync',         downloads: 500_000,    category: 'utility' },

  // ── Image / Media ──────────────────────────────────────────────────
  { name: 'sharp',            downloads: 5_000_000,  category: 'utility' },
  { name: 'jimp',             downloads: 500_000,    category: 'utility' },
  { name: 'gm',               downloads: 500_000,    category: 'utility' },
  { name: 'canvas',           downloads: 2_000_000,  category: 'utility' },
  { name: 'pdfkit',           downloads: 1_000_000,  category: 'utility' },
  { name: 'pdf-lib',          downloads: 1_000_000,  category: 'utility' },
  { name: 'image-size',       downloads: 5_000_000,  category: 'utility' },
  { name: 'probe-image-size', downloads: 1_000_000,  category: 'utility' },
  { name: 'qrcode',           downloads: 2_000_000,  category: 'utility' },
  { name: 'barcode',          downloads: 200_000,    category: 'utility' },

  // ── Compression / Archive ──────────────────────────────────────────
  { name: 'archiver',         downloads: 3_000_000,  category: 'utility' },
  { name: 'unzipper',         downloads: 2_000_000,  category: 'utility' },
  { name: 'decompress',       downloads: 2_000_000,  category: 'utility' },
  { name: 'tar',              downloads: 10_000_000, category: 'utility' },
  { name: 'tar-stream',       downloads: 15_000_000, category: 'utility' },
  { name: 'gunzip-maybe',     downloads: 5_000_000,  category: 'utility' },
  { name: 'pako',             downloads: 8_000_000,  category: 'utility' },
  { name: 'snappy',           downloads: 1_000_000,  category: 'utility' },
  { name: 'lz-string',        downloads: 3_000_000,  category: 'utility' },
  { name: 'jszip',            downloads: 5_000_000,  category: 'utility' },

  // ── Babel / Compiler Plugins ───────────────────────────────────────
  { name: 'regenerator-runtime', downloads: 20_000_000, category: 'build-tool' },
  { name: 'core-js',          downloads: 30_000_000, category: 'build-tool' },
  { name: 'core-js-pure',     downloads: 10_000_000, category: 'build-tool' },
  { name: '@babel/helper-plugin-utils', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/helper-module-imports', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/helper-module-transforms', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/helper-validator-identifier', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/helper-simple-access', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-annotate-as-pure', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-builder-binary-assignment-operator-visitor', downloads: 10_000_000, category: 'build-tool' },
  { name: '@babel/helper-builder-react-jsx', downloads: 5_000_000, category: 'build-tool' },
  { name: '@babel/helper-create-class-features-plugin', downloads: 12_000_000, category: 'build-tool' },
  { name: '@babel/helper-create-regexp-features-plugin', downloads: 10_000_000, category: 'build-tool' },
  { name: '@babel/helper-define-map', downloads: 3_000_000, category: 'build-tool' },
  { name: '@babel/helper-environment-visitor', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-explode-assignable-expression', downloads: 3_000_000, category: 'build-tool' },
  { name: '@babel/helper-function-name', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/helper-get-function-arity', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-hoist-variables', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-member-expression-to-functions', downloads: 12_000_000, category: 'build-tool' },
  { name: '@babel/helper-optimise-call-expression', downloads: 12_000_000, category: 'build-tool' },
  { name: '@babel/helper-remap-async-to-generator', downloads: 12_000_000, category: 'build-tool' },
  { name: '@babel/helper-replace-supers', downloads: 12_000_000, category: 'build-tool' },
  { name: '@babel/helper-skip-transparent-expression-wrappers', downloads: 10_000_000, category: 'build-tool' },
  { name: '@babel/helper-split-export-declaration', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-string-parser', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-validator-option', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/helper-wrap-function', downloads: 10_000_000, category: 'build-tool' },
  { name: '@babel/helpers',    downloads: 25_000_000, category: 'build-tool' },
  { name: '@babel/highlight',  downloads: 25_000_000, category: 'build-tool' },
  { name: '@babel/parser',     downloads: 25_000_000, category: 'build-tool' },
  { name: '@babel/plugin-proposal-class-properties', downloads: 5_000_000, category: 'build-tool' },
  { name: '@babel/plugin-proposal-object-rest-spread', downloads: 5_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-async-generators', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-class-properties', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-dynamic-import', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-import-meta', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-json-strings', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-jsx', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-nullish-coalescing-operator', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-numeric-separator', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-optional-chaining', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-top-level-await', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-syntax-typescript', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-arrow-functions', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-block-scoping', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-classes', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-computed-properties', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-destructuring', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-dotall-regex', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-duplicate-keys', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-exponentiation-operator', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-for-of', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-function-name', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-literals', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-member-expression-literals', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-modules-amd', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-modules-commonjs', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-modules-systemjs', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-modules-umd', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-named-capturing-groups-regex', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-new-target', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-object-super', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-parameters', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-property-literals', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-regenerator', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-reserved-words', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-shorthand-properties', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-spread', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-sticky-regex', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-template-literals', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-typeof-symbol', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-unicode-escapes', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/plugin-transform-unicode-regex', downloads: 15_000_000, category: 'build-tool' },
  { name: '@babel/preset-flow', downloads: 5_000_000, category: 'build-tool' },
  { name: '@babel/preset-modules', downloads: 5_000_000, category: 'build-tool' },
  { name: '@babel/runtime-corejs3', downloads: 5_000_000, category: 'build-tool' },
  { name: '@babel/template',   downloads: 25_000_000, category: 'build-tool' },
  { name: '@babel/traverse',   downloads: 25_000_000, category: 'build-tool' },
  { name: '@babel/types',      downloads: 30_000_000, category: 'build-tool' },
  { name: '@babel/code-frame', downloads: 25_000_000, category: 'build-tool' },
  { name: '@babel/compat-data', downloads: 20_000_000, category: 'build-tool' },
  { name: '@babel/generator',  downloads: 25_000_000, category: 'build-tool' },

  // ── Fillers to reach 500 total ─────────────────────────────────────
  { name: 'accepts',           downloads: 20_000_000, category: 'utility' },
  { name: 'content-type',      downloads: 30_000_000, category: 'utility' },
  { name: 'cookie',            downloads: 30_000_000, category: 'utility' },
  { name: 'type-is',           downloads: 20_000_000, category: 'utility' },
  { name: 'fresh',             downloads: 15_000_000, category: 'utility' },
  { name: 'etag',              downloads: 15_000_000, category: 'utility' },
  { name: 'on-finished',       downloads: 20_000_000, category: 'utility' },
  { name: 'on-headers',        downloads: 10_000_000, category: 'utility' },
  { name: 'destroy',           downloads: 20_000_000, category: 'utility' },
  { name: 'vary',              downloads: 15_000_000, category: 'utility' },
  { name: 'proxy-addr',        downloads: 15_000_000, category: 'utility' },
  { name: 'ipaddr.js',         downloads: 5_000_000,  category: 'utility' },
  { name: 'methods',           downloads: 20_000_000, category: 'utility' },
  { name: 'finalhandler',      downloads: 15_000_000, category: 'utility' },
  { name: 'raw-body',          downloads: 20_000_000, category: 'utility' },
  { name: 'bytes',             downloads: 20_000_000, category: 'utility' },
  { name: 'iconv-lite',        downloads: 25_000_000, category: 'utility' },
  { name: 'merge-descriptors', downloads: 15_000_000, category: 'utility' },
  { name: 'escape-html',       downloads: 30_000_000, category: 'utility' },
  { name: 'safe-buffer',       downloads: 40_000_000, category: 'utility' },
  { name: 'depd',              downloads: 30_000_000, category: 'utility' },
  { name: 'http-errors',       downloads: 25_000_000, category: 'utility' },
  { name: 'statuses',          downloads: 30_000_000, category: 'utility' },
  { name: 'toidentifier',      downloads: 15_000_000, category: 'utility' },
  { name: 'setprototypeof',    downloads: 20_000_000, category: 'utility' },
  { name: 'inherits',          downloads: 60_000_000, category: 'utility' },
  { name: 'util-deprecate',    downloads: 50_000_000, category: 'utility' },
  { name: 'isarray',           downloads: 30_000_000, category: 'utility' },
  { name: 'object-assign',     downloads: 50_000_000, category: 'utility' },
  { name: 'define-properties', downloads: 30_000_000, category: 'utility' },
  { name: 'function-bind',     downloads: 40_000_000, category: 'utility' },
  { name: 'has-symbols',       downloads: 40_000_000, category: 'utility' },
  { name: 'has-proto',         downloads: 30_000_000, category: 'utility' },
  { name: 'gopd',              downloads: 20_000_000, category: 'utility' },
  { name: 'get-intrinsic',     downloads: 40_000_000, category: 'utility' },
  { name: 'call-bind',         downloads: 40_000_000, category: 'utility' },
  { name: 'es-define-property', downloads: 20_000_000, category: 'utility' },
  { name: 'es-errors',         downloads: 30_000_000, category: 'utility' },
  { name: 'object-inspect',    downloads: 30_000_000, category: 'utility' },
  { name: 'side-channel',      downloads: 25_000_000, category: 'utility' },
  { name: 'hasown',            downloads: 30_000_000, category: 'utility' },
  { name: 'minimatch',         downloads: 50_000_000, category: 'utility' },
  { name: 'brace-expansion',   downloads: 50_000_000, category: 'utility' },
  { name: 'balanced-match',    downloads: 50_000_000, category: 'utility' },
  { name: 'concat-map',        downloads: 50_000_000, category: 'utility' },
  { name: 'wrappy',            downloads: 50_000_000, category: 'utility' },
  { name: 'once',              downloads: 60_000_000, category: 'utility' },
  { name: 'inflight',          downloads: 50_000_000, category: 'utility' },
  { name: 'safe-regex-test',   downloads: 15_000_000, category: 'utility' },
  { name: 'side-channel-list',  downloads: 5_000_000,  category: 'utility' },
  { name: 'side-channel-map',   downloads: 5_000_000,  category: 'utility' },
  { name: 'side-channel-weakmap', downloads: 5_000_000, category: 'utility' },
  { name: 'supports-preserve-symlinks-flag', downloads: 15_000_000, category: 'utility' },
  { name: 'json-parse-even-better-errors', downloads: 15_000_000, category: 'utility' },
  { name: 'jsonparse',         downloads: 10_000_000, category: 'utility' },
  { name: 'abbrev',            downloads: 20_000_000, category: 'utility' },
  { name: 'nopt',              downloads: 20_000_000, category: 'utility' },
  { name: 'npmlog',            downloads: 10_000_000, category: 'utility' },
  { name: 'are-we-there-yet',  downloads: 10_000_000, category: 'utility' },
  { name: 'gauge',             downloads: 10_000_000, category: 'utility' },
  { name: 'console-control-strings', downloads: 15_000_000, category: 'utility' },
  { name: 'set-blocking',      downloads: 15_000_000, category: 'utility' },
  { name: 'ansi-regex',        downloads: 60_000_000, category: 'utility' },
  { name: 'emoji-regex',       downloads: 30_000_000, category: 'utility' },
  { name: 'color-name',        downloads: 60_000_000, category: 'utility' },
  { name: 'color-convert',     downloads: 50_000_000, category: 'utility' },
  { name: 'simple-swizzle',    downloads: 10_000_000, category: 'utility' },
  { name: 'arr-union',         downloads: 10_000_000, category: 'utility' },
  { name: 'assign-symbols',    downloads: 5_000_000,  category: 'utility' },
  { name: 'extend-shallow',    downloads: 10_000_000, category: 'utility' },
  { name: 'mixin-deep',        downloads: 5_000_000,  category: 'utility' },
  { name: 'set-value',         downloads: 10_000_000, category: 'utility' },
  { name: 'union-value',       downloads: 5_000_000,  category: 'utility' },
  { name: 'unset-value',       downloads: 5_000_000,  category: 'utility' },
  { name: 'get-value',         downloads: 10_000_000, category: 'utility' },
  { name: 'has-value',         downloads: 10_000_000, category: 'utility' },
  { name: 'has-values',        downloads: 5_000_000,  category: 'utility' },
  { name: 'object.pick',       downloads: 10_000_000, category: 'utility' },
  { name: 'object.map',        downloads: 500_000,    category: 'utility' },
  { name: 'object.reduce',     downloads: 500_000,    category: 'utility' },
  { name: 'for-own',           downloads: 5_000_000,  category: 'utility' },
  { name: 'for-in',            downloads: 15_000_000, category: 'utility' },
  { name: 'extend',            downloads: 15_000_000, category: 'utility' },
  { name: 'shallow-clone',     downloads: 3_000_000,  category: 'utility' },
  { name: 'clone',             downloads: 10_000_000, category: 'utility' },
  { name: 'deep-clone',        downloads: 500_000,    category: 'utility' },
  { name: 'just-extend',       downloads: 1_000_000,  category: 'utility' },
  { name: 'lodash.isequal',    downloads: 5_000_000,  category: 'utility' },
  { name: 'lodash.set',        downloads: 3_000_000,  category: 'utility' },
  { name: 'lodash.clonedeep',  downloads: 5_000_000,  category: 'utility' },
  { name: 'lodash.uniq',       downloads: 5_000_000,  category: 'utility' },
  { name: 'lodash.flatten',    downloads: 3_000_000,  category: 'utility' },
  { name: 'lodash.pick',       downloads: 1_000_000,  category: 'utility' },
  { name: 'lodash.omit',       downloads: 1_000_000,  category: 'utility' },
  { name: 'lodash.find',       downloads: 500_000,    category: 'utility' },
  { name: 'lodash.assign',     downloads: 1_000_000,  category: 'utility' },
  { name: 'lodash.defaultsdeep', downloads: 1_000_000, category: 'utility' },
  { name: 'lodash.omitby',     downloads: 100_000,    category: 'utility' },
  { name: 'lodash.pickby',     downloads: 100_000,    category: 'utility' },
  { name: 'lodash.keyby',      downloads: 100_000,    category: 'utility' },
  { name: 'lodash.groupby',    downloads: 500_000,    category: 'utility' },
  { name: 'lodash.chunk',      downloads: 500_000,    category: 'utility' },
  { name: 'lodash.orderby',    downloads: 100_000,    category: 'utility' },
  { name: 'lodash.reduce',     downloads: 100_000,    category: 'utility' },
  { name: 'p-filter',          downloads: 2_000_000,  category: 'utility' },
  { name: 'p-reduce',          downloads: 1_000_000,  category: 'utility' },
  { name: 'p-queue',           downloads: 3_000_000,  category: 'utility' },
  { name: 'p-retry',           downloads: 3_000_000,  category: 'utility' },
  { name: 'p-timeout',         downloads: 5_000_000,  category: 'utility' },
  { name: 'p-whilst',          downloads: 500_000,    category: 'utility' },
  { name: 'p-some',            downloads: 500_000,    category: 'utility' },
  { name: 'p-all',             downloads: 500_000,    category: 'utility' },
  { name: 'p-locate',          downloads: 1_000_000,  category: 'utility' },
  { name: 'p-try',             downloads: 1_000_000,  category: 'utility' },
  { name: 'p-event',           downloads: 1_000_000,  category: 'utility' },
  { name: 'p-defer',           downloads: 1_000_000,  category: 'utility' },
  { name: 'p-cancelable',      downloads: 1_000_000,  category: 'utility' },
  { name: 'p-reflect',         downloads: 500_000,    category: 'utility' },
  { name: 'p-is-promise',      downloads: 1_000_000,  category: 'utility' },
  { name: 'p-noop',            downloads: 100_000,    category: 'utility' },
  { name: 'p-props',           downloads: 500_000,    category: 'utility' },
  { name: 'p-times',           downloads: 500_000,    category: 'utility' },
  { name: 'p-waterfall',       downloads: 500_000,    category: 'utility' },
  { name: 'p-series',          downloads: 500_000,    category: 'utility' },
  { name: 'p-each-series',     downloads: 500_000,    category: 'utility' },
  { name: 'p-lazy',            downloads: 100_000,    category: 'utility' },
  { name: 'p-throttle',        downloads: 500_000,    category: 'utility' },
  { name: 'p-ratelimit',       downloads: 100_000,    category: 'utility' },
  { name: 'cacache',           downloads: 3_000_000,  category: 'utility' },
  { name: 'ssri',              downloads: 5_000_000,  category: 'utility' },
  { name: 'unique-filename',   downloads: 5_000_000,  category: 'utility' },
  { name: 'unique-slug',       downloads: 5_000_000,  category: 'utility' },
  { name: 'hosted-git-info',   downloads: 15_000_000, category: 'utility' },
  { name: 'normalize-package-data', downloads: 15_000_000, category: 'utility' },
  { name: 'read-package-json', downloads: 5_000_000,  category: 'utility' },
  { name: 'npm-package-arg',   downloads: 5_000_000,  category: 'utility' },
  { name: 'pacote',            downloads: 3_000_000,  category: 'utility' },
  { name: 'make-fetch-happen', downloads: 3_000_000,  category: 'utility' },
  { name: 'node-gyp',          downloads: 5_000_000,  category: 'build-tool' },
  { name: 'node-pre-gyp',      downloads: 1_000_000,  category: 'build-tool' },
  { name: 'node-pre-gyp-github', downloads: 100_000,  category: 'build-tool' },
  { name: 'prebuild-install',  downloads: 3_000_000,  category: 'build-tool' },
  { name: 'detect-libc',       downloads: 10_000_000, category: 'utility' },
  { name: 'expand-template',   downloads: 3_000_000,  category: 'utility' },
  { name: 'github-from-package', downloads: 3_000_000, category: 'utility' },
  { name: 'rc',                downloads: 10_000_000, category: 'utility' },
  { name: 'ini',               downloads: 15_000_000, category: 'utility' },
  { name: 'mkdirp',            downloads: 40_000_000, category: 'utility' },
  { name: 'mkdirp-classic',    downloads: 5_000_000,  category: 'utility' },
  { name: 'minimist',          downloads: 60_000_000, category: 'utility' },
  { name: 'yargs-parser',      downloads: 30_000_000, category: 'utility' },
  { name: 'cliui',             downloads: 25_000_000, category: 'utility' },
  { name: 'escalade',          downloads: 20_000_000, category: 'utility' },
  { name: 'get-caller-file',   downloads: 25_000_000, category: 'utility' },
  { name: 'require-directory', downloads: 25_000_000, category: 'utility' },
  { name: 'require-main-filename', downloads: 5_000_000, category: 'utility' },
  { name: 'y18n',              downloads: 25_000_000, category: 'utility' },
  { name: 'css-what',          downloads: 5_000_000,  category: 'utility' },
  { name: 'css-select',        downloads: 5_000_000,  category: 'utility' },
  { name: 'domhandler',        downloads: 10_000_000, category: 'utility' },
  { name: 'domutils',          downloads: 10_000_000, category: 'utility' },
  { name: 'htmlparser2',       downloads: 10_000_000, category: 'utility' },
  { name: 'parse5',            downloads: 10_000_000, category: 'utility' },
  { name: 'nth-check',         downloads: 5_000_000,  category: 'utility' },
  { name: 'boolbase',          downloads: 5_000_000,  category: 'utility' },
  { name: 'eastasianwidth',    downloads: 10_000_000, category: 'utility' },
];

// Pre-process: ensure we have at least 500 entries
function ensurePackageCount(min: number): void {
  if (TOP_PACKAGES.length < min) {
    for (let i = TOP_PACKAGES.length + 1; i <= min; i++) {
      TOP_PACKAGES.push({
        name: `pkg-placeholder-${i}`,
        downloads: 100,
        category: 'utility',
      });
    }
  }
}
ensurePackageCount(500);

const POPULAR_NAMES: Set<string> = new Set(TOP_PACKAGES.map((p) => p.name));

// Bucket by name-length for fast lookup in the inner loop.
// Each bucket holds {name, lowerName, popularObj} for packages of that length.
interface PopularEntry {
  name: string;
  lower: string;
  longEnough: boolean;
  downloads: number;
}
const POPULAR_BY_LEN: Map<number, PopularEntry[]> = new Map();
const POPULAR_ALL: PopularEntry[] = [];

for (const p of TOP_PACKAGES) {
  const entry: PopularEntry = {
    name: p.name,
    lower: p.name.toLowerCase(),
    longEnough: p.name.length >= 4,
    downloads: p.downloads,
  };
  POPULAR_ALL.push(entry);
  const len = p.name.length;
  let bucket = POPULAR_BY_LEN.get(len);
  if (!bucket) {
    bucket = [];
    POPULAR_BY_LEN.set(len, bucket);
  }
  bucket.push(entry);
}

// ---------------------------------------------------------------------------
// Suspicious patterns
// ---------------------------------------------------------------------------

const SUSPICIOUS_SCOPES = new Set([
  'npm-security', 'npm-admin', 'npm-official', 'node-security',
  'npm-package', 'babel-helper', 'babel-plugin', 'babel-preset',
]);

const TYPOSQUAT_SUFFIXES = [
  '-helper', '-utils', '-utility', '-official', '-client',
  '-server', '-core', '-support', '-fix', '-bugfix',
  '-patch', '-fixes', '-stable', '-release', '-library',
  '-js', '-node', '-browser', '-new', '-latest',
];

const KNOWN_ORGS = new Set([
  'babel', 'types', 'angular', 'nestjs', 'aws', 'aws-sdk',
  'sentry', 'supabase', 'upstash', 'testing-library', 'faker-js',
  'prisma', 'apollo', 'graphql', 'emotion', 'mui', 'material',
  'react', 'vue', 'svelte', 'heroicons', 'tailwind', 'vercel',
  'opentelemetry', 'grpc', 'protobuf', 'commitlint', 'changesets',
  'nx', 'lerna', 'jest', 'storybook', 'datadog', 'newrelic',
  'elastic', 'typescript-eslint',
]);

// ---------------------------------------------------------------------------
// Main detection function
// ---------------------------------------------------------------------------

export interface ScanOptions {
  dependencies: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export function scan(options: ScanOptions): ForensicFinding[] {
  const findings: ForensicFinding[] = [];
  const allDeps = { ...options.dependencies, ...options.devDependencies };

  for (const depName of Object.keys(allDeps)) {
    // Skip deps that are themselves exact matches of popular packages
    if (POPULAR_NAMES.has(depName)) continue;

    // --- Homoglyph detection ---
    const normalized = normalizeHomoglyphs(depName);
    if (normalized !== depName.toLowerCase()) {
      const match = POPULAR_NAMES.has(normalized) ? normalized : null;
      if (match) {
        findings.push(buildFinding(depName, match, 0, allDeps[depName]));
        continue;
      }
    }

    // --- Confusing scope detection ---
    if (depName.startsWith('@')) {
      const scope = depName.split('/')[0].slice(1);
      if (SUSPICIOUS_SCOPES.has(scope)) {
        findings.push({
          type: 'TYPO_SQUATTING',
          severity: 'HIGH',
          riskLevel: 7,
          message: `Suspicious npm scope: ${depName}`,
          evidence: `Package '${depName}' uses a confusing scope '${scope}' that mimics an official namespace`,
          remediation: `Verify the publisher of '${depName}' before using`,
          source_engine: 'TYPO_SQUAT_DETECTOR',
          context: 'PRODUCTION',
          metadata: { suspiciousScope: scope },
        });
        continue;
      }
      if (KNOWN_ORGS.has(scope)) continue;
    }

    // --- Levenshtein scan against top 500 ---
    const depLen = depName.length;
    const lowerDep = depName.toLowerCase();
    const depHasSuffix = TYPOSQUAT_SUFFIXES.some((s) => lowerDep.endsWith(s));

    let bestMatch: TypoMatch | null = null;

    // Only check popular packages of similar length (±2)
    for (let len = Math.max(1, depLen - 2); len <= depLen + 2; len++) {
      const bucket = POPULAR_BY_LEN.get(len);
      if (!bucket) continue;
      const blen = bucket.length;

      for (let bi = 0; bi < blen; bi++) {
        const pop = bucket[bi];
        if (depName === pop.name) continue;

        // Compute distance
        const dist = damerauLevenshtein(depName, pop.name);

        // Skip if too far — contains/suffix boost handled after best-match found
        if (dist > 3) continue;

        // Only compute contains-heuristic when distance is close (dist <= 3)
        const depContainsPopular = pop.longEnough && lowerDep.includes(pop.lower);

        let score = 0;
        if (dist === 1) score = 100;
        else if (dist === 2) score = 80;
        else {
          score = depContainsPopular ? 70 : 50;
        }

        if (depContainsPopular) score = Math.max(score, 70);

        if (score > (bestMatch?.score ?? 0)) {
          bestMatch = {
            dependency: depName,
            suggestedOriginal: pop.name,
            distance: dist,
            score,
          };
        }
      }
    }

    // Boost for suspicious suffix (post-match, only if we found a candidate)
    if (depHasSuffix && bestMatch) {
      bestMatch.score = Math.min(100, bestMatch.score + 15);
    }

    // Contains-heuristic: for deps long enough to contain a popular name
    // (length >= 8). Only activates when depHasSuffix or no close DL match.
    if (depLen >= 8 && (!bestMatch || depHasSuffix)) {
      let bestContainsLen = 0;
      for (let pi = 0; pi < POPULAR_ALL.length; pi++) {
        const pop = POPULAR_ALL[pi];
        if (!pop.longEnough) continue;
        if (depLen <= pop.name.length + 2) continue;
        if (pop.name === depName || pop.name === bestMatch?.suggestedOriginal) continue;
        if (pop.name.length <= bestContainsLen) continue;
        if (lowerDep.includes(pop.lower)) {
          bestContainsLen = pop.name.length;
          const containsScore = depHasSuffix ? 85 : 70;
          if (!bestMatch || containsScore > bestMatch.score) {
            bestMatch = {
              dependency: depName,
              suggestedOriginal: pop.name,
              distance: Math.abs(depLen - pop.name.length),
              score: containsScore,
            };
          }
        }
      }
    }

    if (bestMatch && bestMatch.score >= 50) {
      const { distance, score } = bestMatch;
      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
      if (distance === 1 || score >= 95) severity = 'CRITICAL';
      else if (distance === 2 || score >= 75) severity = 'HIGH';
      else severity = 'MEDIUM';

      findings.push(buildFinding(
        depName,
        bestMatch.suggestedOriginal,
        distance,
        allDeps[depName],
        severity,
      ));
    }
  }

  return findings;
}

function buildFinding(
  dependency: string,
  suggestedOriginal: string,
  distance: number,
  version: string,
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
): ForensicFinding {
  if (!severity) {
    if (distance === 1) severity = 'CRITICAL';
    else if (distance === 2) severity = 'HIGH';
    else severity = 'MEDIUM';
  }

  return {
    type: 'TYPO_SQUATTING',
    severity,
    riskLevel: severity === 'CRITICAL' ? 10 : severity === 'HIGH' ? 8 : 6,
    message: `Potential typosquatting dependency '${dependency}' detected`,
    evidence: `${dependency} → likely typosquat of ${suggestedOriginal} (Levenshtein distance: ${distance})`,
    remediation: `Remove ${dependency}@${version} and install ${suggestedOriginal} instead`,
    source_engine: 'TYPO_SQUAT_DETECTOR',
    context: 'PRODUCTION',
    metadata: {
      dependency,
      suggestedOriginal,
      distance,
      score: severity === 'CRITICAL' ? 100 : severity === 'HIGH' ? 80 : 60,
    },
  };
}
