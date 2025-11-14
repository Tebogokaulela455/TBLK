// controllers/invoiceController.js
const Invoice = require('../models/invoiceModel');

// Generate an invoice
async function generateInvoice(req, res) {
  const { clientId, policyId, amount, type } = req.body;
  try {
    const result = await Invoice.generateInvoice(clientId, policyId, amount, type);
    res.status(201).json({ message: 'Invoice generated successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Error generating invoice.' });
  }
}

// List invoices
async function listInvoices(req, res) {
  try {
    const invoices = await Invoice.listInvoices();
    res.json(invoices);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching invoices.' });
  }
}

module.exports = { generateInvoice, listInvoices };