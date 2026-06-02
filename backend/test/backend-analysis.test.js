const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { scanBackendApiSecurity } = require('../src/scanner/backend-analysis.service');

describe('Backend analysis service', () => {
  let tempDir;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'backend-analysis-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  test('detects unsafe CORS and missing auth on admin route', async () => {
    const appCode = `const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.get('/admin', (req, res) => res.send('admin'));
app.get('/health', (req, res) => res.send('ok'));
module.exports = app;`;
    await fs.writeFile(path.join(tempDir, 'index.js'), appCode, 'utf8');

    const findings = await scanBackendApiSecurity(tempDir);
    const titles = findings.map((finding) => finding.title);

    expect(titles).toEqual(expect.arrayContaining([
      'Unsafe CORS configuration detected',
      'Missing authentication for route /admin',
      'Missing authorization for admin route /admin',
      'Platform missing API rate limiting'
    ]));
  });

  test('detects controller -> service -> repository cross-file flow', async () => {
    const controllerCode = `const service = require('./service');
module.exports.create = function create(req, res) {
  return service.process(req.body);
};`;
    const serviceCode = `const repository = require('./repository');
module.exports.process = function process(payload) {
  return repository.save(payload);
};`;
    const repositoryCode = `const pool = require('pg').Pool;
module.exports.save = function save(data) {
  return pool.query('insert into items (payload) values ($1)', [data]);
};`;

    await fs.writeFile(path.join(tempDir, 'controller.js'), controllerCode, 'utf8');
    await fs.writeFile(path.join(tempDir, 'service.js'), serviceCode, 'utf8');
    await fs.writeFile(path.join(tempDir, 'repository.js'), repositoryCode, 'utf8');

    const findings = await scanBackendApiSecurity(tempDir);
    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          title: 'Cross-file controller/service/repository flow detected',
          category: 'Data flow analysis',
          severity: 'medium'
        })
      ])
    );
  });
});
