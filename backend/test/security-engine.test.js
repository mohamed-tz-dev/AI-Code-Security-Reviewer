const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { scanDependencyFiles } = require('../src/scanner/dependency-vulnerability.service');
const { scanFileWithSecretPatterns } = require('../src/scanner/secret-detection.service');

describe('Security engine enhancements', () => {
  let tempDir;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-security-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  test('detects outdated dependencies in package.json', async () => {
    const packageJson = {
      dependencies: {
        lodash: '4.17.15',
        axios: '^0.20.0',
        express: '4.18.2'
      },
      devDependencies: {
        jest: '^29.0.0'
      }
    };

    await fs.writeFile(path.join(tempDir, 'package.json'), JSON.stringify(packageJson, null, 2), 'utf8');

    const findings = await scanDependencyFiles(tempDir);

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          title: 'Outdated Lodash dependency',
          category: 'Dependency issues',
          severity: 'high'
        }),
        expect.objectContaining({
          title: 'Outdated axios dependency',
          category: 'Dependency issues',
          severity: 'high'
        })
      ])
    );
  });

  test('detects hardcoded secrets in file content', () => {
    const findings = scanFileWithSecretPatterns(
      { relativePath: 'src/secrets.js' },
      "const apiKey = 'AKIA1234567890ABCD';\nconst token = 'ghp_1234567890abcdef1234';"
    );

    expect(findings).toHaveLength(2);
    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          title: 'Possible hardcoded API secret',
          category: 'Hardcoded secrets',
          severity: 'high',
          filePath: 'src/secrets.js'
        }),
        expect.objectContaining({
          title: 'Possible GitHub personal access token',
          category: 'Hardcoded secrets',
          severity: 'high',
          filePath: 'src/secrets.js'
        })
      ])
    );
  });
});
