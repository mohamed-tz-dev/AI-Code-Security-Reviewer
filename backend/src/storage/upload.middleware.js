const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const { env } = require('../config/env');

fs.mkdirSync(env.uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination(_req, _file, cb) {
    cb(null, env.uploadDir);
  },
  filename(_req, file, cb) {
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
    const safeName = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${uniqueSuffix}-${safeName}`);
  }
});

function fileFilter(_req, file, cb) {
  const extension = path.extname(file.originalname).toLowerCase();
  const isZip =
    extension === '.zip' ||
    file.mimetype === 'application/zip' ||
    file.mimetype === 'application/x-zip-compressed' ||
    file.mimetype === 'application/octet-stream';

  if (!isZip) {
    const error = new Error('Only .zip uploads are supported.');
    error.statusCode = 400;
    cb(error);
    return;
  }

  cb(null, true);
}

const uploadZip = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: env.maxUploadMb * 1024 * 1024,
    files: 1
  }
});

module.exports = { uploadZip };
