const express = require('express');

const { asyncHandler } = require('../../lib/async-handler');
const { attachCurrentUser, requireAdmin } = require('../../middleware/auth.middleware');
const { uploadZip } = require('../../storage/upload.middleware');
const scanController = require('./scan.controller');

const scanRoutes = express.Router();

scanRoutes.use(asyncHandler(attachCurrentUser));
scanRoutes.get('/', asyncHandler(scanController.listScans));
scanRoutes.get('/admin/summary', requireAdmin, asyncHandler(scanController.getAdminSummary));
scanRoutes.get('/ci-templates', asyncHandler(scanController.listCiTemplates));
scanRoutes.get('/ci-templates/:provider', asyncHandler(scanController.getCiTemplate));
scanRoutes.get('/:scanId/export.pdf', asyncHandler(scanController.exportScanPdf));
scanRoutes.get('/:scanId', asyncHandler(scanController.getScan));
scanRoutes.post('/zip', uploadZip.single('repository'), asyncHandler(scanController.createZipScan));
scanRoutes.post('/github', asyncHandler(scanController.createGithubScan));
scanRoutes.post('/chat', asyncHandler(scanController.askChat));

module.exports = { scanRoutes };
