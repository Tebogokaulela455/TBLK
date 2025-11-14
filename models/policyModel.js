const pool = require('../config');

// Add a new policy
async function addPolicy(clientId, policyNumber, type, premium, startDate, endDate) {
  const sql = 'INSERT INTO policies (clientId, policyNumber, type, premium, startDate, endDate) VALUES (?, ?, ?, ?, ?, ?)';
  const [result] = await pool.execute(sql, [clientId, policyNumber, type, premium, startDate, endDate]);
  return result;
}

// List policies
async function listPolicies() {
  const sql = 'SELECT * FROM policies';
  const [rows] = await pool.execute(sql);
  return rows;
}

module.exports = { addPolicy, listPolicies };
