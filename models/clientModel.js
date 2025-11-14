const pool = require('../config');

// Add a new client
async function addClient(name, phone, email, address) {
  const sql = 'INSERT INTO clients (name, phone, email, address) VALUES (?, ?, ?, ?)';
  const [result] = await pool.execute(sql, [name, phone, email, address]);
  return result;
}

// List clients
async function listClients() {
  const sql = 'SELECT * FROM clients';
  const [rows] = await pool.execute(sql);
  return rows;
}

module.exports = { addClient, listClients };
