const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES_PER_SCAN = 3000;
const MAX_ZIP_ENTRIES = 10000;
const MAX_ZIP_ENTRY_BYTES = 10 * 1024 * 1024;

const IGNORED_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  'coverage',
  'dist',
  'build',
  'out',
  'target',
  'bin',
  'obj',
  'node_modules',
  'vendor',
  '__pycache__'
]);

const IGNORED_FILE_NAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',
  'poetry.lock',
  'go.sum'
]);

const SOURCE_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.php',
  '.rb',
  '.go',
  '.java',
  '.cs',
  '.c',
  '.cc',
  '.cpp',
  '.h',
  '.hpp',
  '.rs',
  '.swift',
  '.kt',
  '.kts',
  '.scala',
  '.sql',
  '.html',
  '.vue',
  '.svelte',
  '.env',
  '.yaml',
  '.yml',
  '.json',
  '.toml',
  '.ini'
]);

const BINARY_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.7z',
  '.rar',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.class',
  '.jar',
  '.wasm',
  '.mp3',
  '.mp4',
  '.mov',
  '.avi',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot'
]);

module.exports = {
  BINARY_EXTENSIONS,
  IGNORED_DIRECTORIES,
  IGNORED_FILE_NAMES,
  MAX_FILE_BYTES,
  MAX_FILES_PER_SCAN,
  MAX_ZIP_ENTRIES,
  MAX_ZIP_ENTRY_BYTES,
  SOURCE_EXTENSIONS
};
