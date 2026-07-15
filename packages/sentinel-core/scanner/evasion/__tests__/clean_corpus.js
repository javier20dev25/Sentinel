'use strict';

const SAMPLES = {

  expressServer: `
const express = require('express');
const app = express();
app.get('/', (req, res) => {
  res.send('Hello World');
});
app.listen(3000);
`,

  asyncFileRead: `
const fs = require('fs').promises;
async function readConfig(path) {
  try {
    const data = await fs.readFile(path, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Failed to read config:', err.message);
    return {};
  }
}
`,

  buildScript: `
const { execSync } = require('child_process');
try {
  execSync('npm run build', { stdio: 'inherit' });
  console.log('Build complete');
} catch (err) {
  process.exit(1);
}
`,

  unitTestEval: `
describe('calculator', () => {
  it('evaluates expression', () => {
    const result = eval('2 + 2');
    expect(result).toBe(4);
  });
});
`,

  base64ImageData: `
const imgData = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
`,

  setTimeoutDelay: `
function debounce(fn, delay) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}
`,

  requireMultiple: `
const _ = require('lodash');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
`,

  cryptoHashing: `
const crypto = require('crypto');
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
`,

  axiosRequest: `
const axios = require('axios');
async function fetchData(url) {
  const response = await axios.get(url, {
    headers: { 'Accept': 'application/json' },
    timeout: 5000,
  });
  return response.data;
}
`,

  npmScript: `
{
  "name": "my-package",
  "scripts": {
    "start": "node server.js",
    "test": "jest",
    "build": "webpack --mode production",
    "postinstall": "node setup.js"
  }
}
`,

  envConfig: `
const config = {
  port: process.env.PORT || 3000,
  dbUrl: process.env.DATABASE_URL,
  redisHost: process.env.REDIS_HOST || 'localhost',
};
`,

  lodashTemplate: `
const result = _.template('hello <%= user %>!')({ user: 'fred' });
`,

  tryCatchRequire: `
let mod;
try {
  mod = require('optional-dep');
} catch (e) {
  mod = null;
}
`,

  promiseAll: `
async function processAll(items) {
  const results = await Promise.all(items.map(async (item) => {
    const data = await fetchItem(item);
    return transform(data);
  }));
  return results;
}
`,

  httpServer: `
const http = require('http');
const server = http.createServer((req, res) => {
  res.writeHead(200);
  res.end('ok');
});
server.listen(8080);
`,

  classComponent: `
class UserService {
  constructor(db) {
    this.db = db;
  }
  async findById(id) {
    return this.db.users.findOne({ where: { id } });
  }
  async create(data) {
    return this.db.users.create(data);
  }
}
`,

  reactSetState: `
function Counter() {
  const [count, setCount] = React.useState(0);
  return React.createElement('button', {
    onClick: () => setCount(c => c + 1)
  }, count);
}
`,

  webpackConfig: `
module.exports = {
  entry: './src/index.js',
  output: { filename: 'bundle.js' },
  module: {
    rules: [
      { test: /\\.js$/, use: 'babel-loader' }
    ]
  }
};
`,

  dotenvUsage: `
require('dotenv').config();
const db = require('./db');
db.connect(process.env.MONGO_URI);
`,

  graphqlSchema: `
const { gql } = require('apollo-server');
const typeDefs = gql\`
  type Query {
    hello: String
    users: [User]
  }
  type User {
    id: ID!
    name: String!
  }
\`;
`,
};

module.exports = SAMPLES;
