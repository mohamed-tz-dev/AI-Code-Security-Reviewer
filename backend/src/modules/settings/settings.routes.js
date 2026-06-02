const express = require('express');

const { asyncHandler } = require('../../lib/async-handler');
const { attachCurrentUser, requireAdmin } = require('../../middleware/auth.middleware');
const settingsController = require('./settings.controller');

const settingsRoutes = express.Router();

settingsRoutes.use(asyncHandler(attachCurrentUser));
settingsRoutes.get('/', asyncHandler(settingsController.getSettings));
settingsRoutes.patch('/', requireAdmin, asyncHandler(settingsController.updateSettings));

module.exports = { settingsRoutes };
