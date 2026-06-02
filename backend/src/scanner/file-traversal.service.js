const fs = require('fs/promises');
const path = require('path');

const {
  BINARY_EXTENSIONS,
  IGNORED_DIRECTORIES,
  IGNORED_FILE_NAMES,
  MAX_FILE_BYTES,
  MAX_FILES_PER_SCAN,
  SOURCE_EXTENSIONS
} = require('./scanner.config');

function toRelativePath(rootPath, filePath) {
  return path.relative(rootPath, filePath).split(path.sep).join('/');
}

function shouldIgnoreDirectory(directoryName) {
  return IGNORED_DIRECTORIES.has(directoryName);
}

function shouldScanFile(fileName) {
  const extension = path.extname(fileName).toLowerCase();

  if (IGNORED_FILE_NAMES.has(fileName)) {
    return false;
  }

  if (BINARY_EXTENSIONS.has(extension)) {
    return false;
  }

  return SOURCE_EXTENSIONS.has(extension);
}

async function isProbablyTextFile(filePath) {
  const handle = await fs.open(filePath, 'r');

  try {
    const buffer = Buffer.alloc(512);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);

    for (let index = 0; index < bytesRead; index += 1) {
      if (buffer[index] === 0) {
        return false;
      }
    }

    return true;
  } finally {
    await handle.close();
  }
}

async function collectSourceFiles(repositoryPath) {
  const files = [];

  async function walk(currentPath) {
    if (files.length >= MAX_FILES_PER_SCAN) {
      return;
    }

    const entries = await fs.readdir(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const absolutePath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        if (!shouldIgnoreDirectory(entry.name)) {
          await walk(absolutePath);
        }
        continue;
      }

      if (!entry.isFile() || !shouldScanFile(entry.name)) {
        continue;
      }

      const stats = await fs.stat(absolutePath);
      if (stats.size > MAX_FILE_BYTES) {
        continue;
      }

      if (!(await isProbablyTextFile(absolutePath))) {
        continue;
      }

      files.push({
        absolutePath,
        relativePath: toRelativePath(repositoryPath, absolutePath),
        sizeBytes: stats.size
      });

      if (files.length >= MAX_FILES_PER_SCAN) {
        return;
      }
    }
  }

  await walk(repositoryPath);
  return files;
}

module.exports = { collectSourceFiles };
