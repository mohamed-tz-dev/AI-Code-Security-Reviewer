const fs = require('fs');
const path = require('path');
const parser = require('@babel/parser');

const { mapToOwaspCategory } = require('./owasp-map');
const { collectSourceFiles } = require('./file-traversal.service');

const ROUTE_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'all', 'head', 'options', 'use']);
const SAFE_PUBLIC_PATHS = ['/health', '/status', '/login', '/logout', '/signup', '/auth', '/public'];
const KNOWN_AUTH_NAMES = new Set([
  'attachCurrentUser',
  'requireAdmin',
  'authenticate',
  'authorize',
  'requireAuth',
  'verifyToken',
  'isAuthenticated',
  'ensureAuth',
  'checkAuth',
  'auth',
  'authMiddleware'
]);
const KNOWN_RATE_LIMIT_PACKAGES = new Set(['express-rate-limit', 'rate-limit', 'rateLimiter']);

function walkAst(node, visitor, parent = null) {
  if (!node || typeof node !== 'object') return;

  visitor(node, parent);

  for (const key of Object.keys(node)) {
    if (['loc', 'start', 'end', 'extra', 'leadingComments', 'trailingComments'].includes(key)) {
      continue;
    }

    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        walkAst(child, visitor, node);
      }
      continue;
    }

    if (value?.type) {
      walkAst(value, visitor, node);
    }
  }
}

function parseJavaScript(content) {
  try {
    return parser.parse(content, {
      sourceType: 'unambiguous',
      plugins: [
        'jsx',
        'typescript',
        'classProperties',
        'decorators-legacy',
        'dynamicImport',
        'objectRestSpread',
        'optionalChaining',
        'topLevelAwait'
      ]
    });
  } catch (_error) {
    return null;
  }
}

function getIdentifierName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') return getIdentifierName(node.property);
  return null;
}

function isLocalModule(specifier) {
  return typeof specifier === 'string' && (specifier.startsWith('./') || specifier.startsWith('../'));
}

function resolveLocalModulePath(filePath, sourceValue) {
  if (!isLocalModule(sourceValue)) return null;
  const base = path.resolve(path.dirname(filePath), sourceValue);
  const candidates = [
    base,
    `${base}.js`,
    `${base}.jsx`,
    `${base}.ts`,
    `${base}.tsx`,
    path.join(base, 'index.js'),
    path.join(base, 'index.jsx'),
    path.join(base, 'index.ts'),
    path.join(base, 'index.tsx')
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return path.normalize(candidate).replace(/\\/g, '/');
    }
  }

  return path.normalize(base).replace(/\\/g, '/');
}

function collectLocalImports(filePath, ast) {
  const imports = [];

  walkAst(ast, (node) => {
    if (node.type === 'ImportDeclaration' && isLocalModule(node.source.value)) {
      const sourcePath = resolveLocalModulePath(filePath, node.source.value);
      for (const specifier of node.specifiers) {
        const localName = specifier.local.name;
        imports.push({ localName, sourcePath });
      }
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.init?.type === 'CallExpression' &&
      node.init.callee.type === 'Identifier' &&
      node.init.callee.name === 'require' &&
      node.init.arguments.length === 1 &&
      node.init.arguments[0].type === 'StringLiteral' &&
      isLocalModule(node.init.arguments[0].value)
    ) {
      const sourcePath = resolveLocalModulePath(filePath, node.init.arguments[0].value);
      if (node.id.type === 'ObjectPattern') {
        for (const property of node.id.properties) {
          const localName = property.value?.name || property.key?.name;
          if (localName) {
            imports.push({ localName, sourcePath });
          }
        }
      } else if (node.id.type === 'Identifier') {
        imports.push({ localName: node.id.name, sourcePath });
      }
    }
  });

  return imports;
}

function collectTopLevelUseMiddleware(ast) {
  const middlewareNames = new Set();
  walkAst(ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const callee = node.callee;
    if (callee.type !== 'MemberExpression') return;
    const method = getIdentifierName(callee.property);
    if (method !== 'use') return;

    for (const arg of node.arguments) {
      const name = getIdentifierName(arg) || (arg.type === 'Identifier' && arg.name);
      if (name) {
        middlewareNames.add(name);
      }
    }
  });
  return middlewareNames;
}

function matchesSafePublicPath(routePath) {
  if (!routePath || typeof routePath !== 'string') return false;
  return SAFE_PUBLIC_PATHS.some((safePath) => routePath.startsWith(safePath));
}

function collectRoutes(ast) {
  const routes = [];
  const routeVariables = new Set(['app', 'router']);

  walkAst(ast, (node) => {
    if (node.type === 'VariableDeclarator' && node.init?.type === 'CallExpression') {
      const calleeName = getIdentifierName(node.init.callee);
      if (calleeName === 'Router' || calleeName === 'express') {
        if (node.id.type === 'Identifier') {
          routeVariables.add(node.id.name);
        }
      }
    }

    if (node.type !== 'CallExpression') return;
    const callee = node.callee;
    if (callee.type !== 'MemberExpression') return;

    const objectName = getIdentifierName(callee.object);
    const methodName = getIdentifierName(callee.property);
    if (!routeVariables.has(objectName) || !ROUTE_METHODS.has(methodName)) return;

    const routeArg = node.arguments[0];
    const routePath = routeArg?.type === 'StringLiteral' ? routeArg.value : null;
    const middlewares = node.arguments.slice(1, -1).map((arg) => getIdentifierName(arg)).filter(Boolean);
    const handler = node.arguments[node.arguments.length - 1];
    const handlerName = getIdentifierName(handler) || (handler.type === 'Identifier' && handler.name);

    const hasAuthMiddleware = middlewares.some((name) => KNOWN_AUTH_NAMES.has(name));
    const hasAdminMiddleware = middlewares.some((name) => /requireAdmin|authorize|admin/i.test(name));

    routes.push({ methodName, routePath, hasAuthMiddleware, hasAdminMiddleware, handlerName, objectName });
  });

  return routes;
}

function collectCorsUsage(ast) {
  const corsCalls = [];

  walkAst(ast, (node) => {
    if (node.type !== 'CallExpression') return;
    if (node.callee.type !== 'Identifier' || node.callee.name !== 'cors') return;

    const optionsArg = node.arguments[0];
    const isOpen = !optionsArg ||
      (optionsArg.type === 'ObjectExpression' && optionsArg.properties.some((property) => {
        const keyName = getIdentifierName(property.key);
        if (keyName !== 'origin') return false;
        if (!property.value) return false;
        if (property.value.type === 'StringLiteral' && property.value.value === '*') return true;
        return false;
      }));

    corsCalls.push({ open: isOpen, hasOptions: Boolean(optionsArg) });
  });

  return corsCalls;
}

function collectRateLimitUsage(ast, fileContent) {
  let hasRateLimit = false;
  walkAst(ast, (node) => {
    if (hasRateLimit) return;
    if (node.type === 'CallExpression' && getIdentifierName(node.callee) === 'rateLimit') {
      hasRateLimit = true;
    }
    if (node.type === 'ImportDeclaration' && KNOWN_RATE_LIMIT_PACKAGES.has(node.source.value)) {
      hasRateLimit = true;
    }
  });
  if (!hasRateLimit && /require\(['"]express-rate-limit['"]\)/.test(fileContent)) {
    hasRateLimit = true;
  }
  return hasRateLimit;
}

function collectDatabaseUsage(ast) {
  let usesQuery = false;
  walkAst(ast, (node) => {
    if (usesQuery) return;
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const property = getIdentifierName(node.callee.property);
      const object = getIdentifierName(node.callee.object);
      if (property === 'query' && ['pool', 'client', 'db', 'database'].includes(object)) {
        usesQuery = true;
      }
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && getIdentifierName(node.callee) === 'query') {
      usesQuery = true;
    }
  });
  return usesQuery;
}

function collectRequestSources(ast) {
  const requestSources = new Set();
  walkAst(ast, (node, parent) => {
    if (node.type !== 'MemberExpression') return;
    if (node.object.type === 'Identifier' && node.object.name === 'req') {
      const propertyName = getIdentifierName(node.property);
      if (['body', 'params', 'query', 'headers', 'cookies'].includes(propertyName)) {
        requestSources.add(propertyName);
      }
    }
  });
  return requestSources;
}

function buildCrossFileFlowFindings(filesByPath) {
  const findings = [];
  const controllers = [];
  const services = new Map();
  const repositories = new Map();

  for (const fileInfo of Object.values(filesByPath)) {
    const relativePath = fileInfo.relativePath.toLowerCase();
    if (relativePath.includes('/controller') || relativePath.includes('controller.') || relativePath.includes('/routes/')) {
      controllers.push(fileInfo);
    }
    if (relativePath.includes('/service') || relativePath.includes('service.')) {
      services.set(fileInfo.normalizedPath, fileInfo);
    }
    if (relativePath.includes('/repository') || relativePath.includes('repository.')) {
      repositories.set(fileInfo.normalizedPath, fileInfo);
    }
  }

  for (const controller of controllers) {
    const importedServices = new Set();
    for (const imported of controller.imports) {
      if (services.has(imported.sourcePath)) {
        importedServices.add(services.get(imported.sourcePath));
      }
    }

    for (const service of importedServices) {
      const importedRepositories = new Set();
      for (const imported of service.imports) {
        if (repositories.has(imported.sourcePath)) {
          importedRepositories.add(repositories.get(imported.sourcePath));
        }
      }

      for (const repository of importedRepositories) {
        if (repository.usesDatabase) {
          const chain = [controller.relativePath, service.relativePath, repository.relativePath].join(' → ');
          findings.push({
            title: 'Cross-file controller/service/repository flow detected',
            category: 'Data flow analysis',
            severity: 'medium',
            filePath: controller.relativePath,
            lineStart: null,
            lineEnd: null,
            description: `Detected a cross-file flow chain through ${chain}. This indicates controller logic flows into service and repository layers, which is useful for deeper taint and authorization analysis.`,            recommendation: 'Review this layered flow for proper input validation, authorization checks, and SQL query safety.',
            evidence: chain,
            confidence: 0.75,
            owasp_category: mapToOwaspCategory('Data flow analysis', 'Cross-file controller/service/repository flow')
          });
        }
      }
    }
  }

  return findings;
}

function buildRouteSecurityFindings(fileInfo) {
  const findings = [];
  const { relativePath, routeDefinitions, corsUsage, hasRateLimit, hasAuthTopLevel } = fileInfo;

  if (corsUsage.some((entry) => entry.open)) {
    findings.push({
      title: 'Unsafe CORS configuration detected',
      category: 'API security',
      severity: 'high',
      filePath: relativePath,
      lineStart: null,
      lineEnd: null,
      description: 'The repository enables CORS without origin restrictions, which may expose the API to cross-origin abuse.',
      recommendation: 'Restrict CORS to specific trusted origins and avoid using a wildcard origin in production.',
      evidence: 'cors() with default or wildcard origin',
      confidence: 0.85,
      owasp_category: mapToOwaspCategory('CORS', 'Security misconfiguration')
    });
  }

  if (!hasRateLimit && routeDefinitions.length > 0) {
    findings.push({
      title: 'Rate limiting is not configured',
      category: 'API security',
      severity: 'medium',
      filePath: relativePath,
      lineStart: null,
      lineEnd: null,
      description: 'No rate limiting middleware was detected in this file, increasing exposure to brute force and denial-of-service abuse.',
      recommendation: 'Add API rate limiting middleware such as express-rate-limit to protect public endpoints.',
      evidence: 'No rateLimit import or invocation detected',
      confidence: 0.7,
      owasp_category: mapToOwaspCategory('Rate limiting', 'Security misconfiguration')
    });
  }

  for (const route of routeDefinitions) {
    if (!route.routePath) continue;
    if (matchesSafePublicPath(route.routePath)) continue;

    const isAdminRoute = /\badmin\b/.test(route.routePath.toLowerCase()) || relativePath.toLowerCase().includes('/admin');

    if (!route.hasAuthMiddleware && !hasAuthTopLevel && !matchesSafePublicPath(route.routePath)) {
      findings.push({
        title: `Missing authentication for route ${route.routePath}`,
        category: 'Authentication issues',
        severity: 'high',
        filePath: relativePath,
        lineStart: null,
        lineEnd: null,
        description: `The route ${route.methodName.toUpperCase()} ${route.routePath} does not appear to require authentication or use authentication middleware.`,
        recommendation: 'Require authentication middleware for non-public API endpoints.',
        evidence: `${route.methodName.toUpperCase()} ${route.routePath}`,
        confidence: 0.8,
        owasp_category: mapToOwaspCategory('Authentication', 'Missing auth middleware')
      });
    }

    if (isAdminRoute && !route.hasAdminMiddleware && !route.hasAuthMiddleware && !hasAuthTopLevel) {
      findings.push({
        title: `Missing authorization for admin route ${route.routePath}`,
        category: 'Authorization issues',
        severity: 'high',
        filePath: relativePath,
        lineStart: null,
        lineEnd: null,
        description: `The admin endpoint ${route.routePath} does not appear to require an admin authorization check.`,
        recommendation: 'Add an authorization middleware such as requireAdmin for admin routes.',
        evidence: `${route.methodName.toUpperCase()} ${route.routePath}`,
        confidence: 0.8,
        owasp_category: mapToOwaspCategory('Authorization', 'Missing admin check')
      });
    }
  }

  return findings;
}

async function scanBackendApiSecurity(repositoryPath) {
  const sourceFiles = await collectSourceFiles(repositoryPath);
  const codeFiles = sourceFiles.filter((file) => ['.js', '.jsx', '.ts', '.tsx'].includes(path.extname(file.relativePath).toLowerCase()));
  const fileInfoByPath = {};
  let globalRateLimitDetected = false;

  for (const sourceFile of codeFiles) {
    const content = await require('fs/promises').readFile(sourceFile.absolutePath, 'utf8');
    const ast = parseJavaScript(content);
    if (!ast) continue;

    const imports = collectLocalImports(sourceFile.absolutePath, ast);
    const routeDefinitions = collectRoutes(ast);
    const corsUsage = collectCorsUsage(ast);
    const hasRateLimit = collectRateLimitUsage(ast, content);
    const hasAuthTopLevel = Array.from(collectTopLevelUseMiddleware(ast)).some((name) => KNOWN_AUTH_NAMES.has(name));
    const usesDatabase = collectDatabaseUsage(ast);
    const requestSources = collectRequestSources(ast);

    if (hasRateLimit) globalRateLimitDetected = true;

    fileInfoByPath[sourceFile.absolutePath] = {
      normalizedPath: path.normalize(sourceFile.absolutePath).replace(/\\/g, '/'),
      relativePath: sourceFile.relativePath,
      imports,
      routeDefinitions,
      corsUsage,
      hasRateLimit,
      hasAuthTopLevel,
      usesDatabase,
      requestSources
    };
  }

  const findings = [];
  const backendFileInfos = Object.values(fileInfoByPath);

  for (const fileInfo of backendFileInfos) {
    findings.push(...buildRouteSecurityFindings(fileInfo));
  }

  if (!globalRateLimitDetected && backendFileInfos.some((info) => info.routeDefinitions.length > 0)) {
    findings.push({
      title: 'Platform missing API rate limiting',
      category: 'API security',
      severity: 'medium',
      filePath: 'repository-wide',
      lineStart: null,
      lineEnd: null,
      description: 'No API rate limiting middleware was detected across the repository, leaving endpoints vulnerable to abuse.',
      recommendation: 'Add rate limiting to entry points and public routes to reduce brute force and denial-of-service exposure.',
      evidence: 'No rateLimit usage in codebase',
      confidence: 0.75,
      owasp_category: mapToOwaspCategory('Rate limiting', 'Security misconfiguration')
    });
  }

  findings.push(...buildCrossFileFlowFindings(fileInfoByPath));

  return findings;
}

module.exports = { scanBackendApiSecurity };
