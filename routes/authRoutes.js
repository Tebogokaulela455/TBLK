// routes/authRoutes.js
const express = require('express');
const { register, login, approveUser } = require('../controllers/authController');
const router = express.Router();

// User registration route
router.post('/register', register);

// User login route
router.post('/login', login);

// Admin approval route
router.post('/approve/:id', approveUser);

module.exports = router;