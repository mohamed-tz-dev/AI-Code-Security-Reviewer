const express = require('express');

const { asyncHandler } = require('../../lib/async-handler');
const { attachCurrentUser } = require('../../middleware/auth.middleware');
const authController = require('./auth.controller');

const authRoutes = express.Router();

authRoutes.post('/register',    asyncHandler(authController.register));
authRoutes.post('/login',       asyncHandler(authController.login));
authRoutes.post('/admin/login', asyncHandler(authController.adminLogin));
authRoutes.post('/google',      asyncHandler(authController.googleAuth));
authRoutes.post('/clerk',       asyncHandler(authController.clerkAuth));
authRoutes.get('/me', asyncHandler(attachCurrentUser), asyncHandler(authController.me));

module.exports = { authRoutes };

