const express = require('express');

const { asyncHandler } = require('../../lib/async-handler');
const { attachCurrentUser, requireAdmin } = require('../../middleware/auth.middleware');
const adminController = require('./admin.controller');

const adminRoutes = express.Router();

adminRoutes.use(asyncHandler(attachCurrentUser));
adminRoutes.use(requireAdmin);
adminRoutes.get('/audit-logs', asyncHandler(adminController.listAuditLogs));
adminRoutes.get('/users', asyncHandler(adminController.listUsers));
adminRoutes.patch('/users/:userId/role', express.json(), asyncHandler(adminController.updateUserRole));

module.exports = { adminRoutes };
