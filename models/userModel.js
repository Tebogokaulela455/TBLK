const bcrypt = require('bcryptjs');

const pool = require('../config');

// User Registration & Approval
async function createUser(username, email, password) {
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = 'INSERT INTO users (username, email, password, isApproved, role) VALUES (?, ?, ?, false, "user")';
  const [result] = await pool.execute(sql, [username, email, hashedPassword]);
  return result;
}

// Approve User
async function approveUser(userId) {
  const sql = 'UPDATE users SET isApproved = true WHERE id = ?';
  const [result] = await pool.execute(sql, [userId]);
  return result;
}

// Get User by Email
async function getUserByEmail(email) {
  const sql = 'SELECT * FROM users WHERE email = ?';
  const [rows] = await pool.execute(sql, [email]);
  return rows[0];
}

// Get User by ID
async function getUserById(id) {
  const sql = 'SELECT * FROM users WHERE id = ?';
  const [rows] = await pool.execute(sql, [id]);
  return rows[0];
}

// Check password
async function checkPassword(storedPassword, enteredPassword) {
  return bcrypt.compare(enteredPassword, storedPassword);
}

module.exports = { createUser, approveUser, getUserByEmail, getUserById, checkPassword };
