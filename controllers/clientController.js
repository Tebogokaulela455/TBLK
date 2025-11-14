const Client = require('../models/clientModel');

// Add a new client
async function addClient(req, res) {
  const { name, phone, email, address } = req.body;
  try {
    const result = await Client.addClient(name, phone, email, address);
    // Placeholder for sending welcome SMS
    res.status(201).json({ message: 'Client added successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Error adding client.' });
  }
}

// List all clients
async function listClients(req, res) {
  try {
    const clients = await Client.listClients();
    res.json(clients);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching clients.' });
  }
}

module.exports = { addClient, listClients };