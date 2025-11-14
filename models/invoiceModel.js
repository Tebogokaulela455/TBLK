const pool = require('../config');

// Generate an invoice
async function generateInvoice(clientId, policyId, amount, type) {
  const sql = 'INSERT INTO invoices (clientId, policyId, amount, type) VALUES (?, ?, ?, ?)';
  const [result] = await pool.execute(sql, [clientId, policyId, amount, type]);
  return result;
}

// List invoices
async function listInvoices() {
  const sql = 'SELECT * FROM invoices';
  const [rows] = await pool.execute(sql);
  return rows;
}

module.exports = { generateInvoice, listInvoices };
