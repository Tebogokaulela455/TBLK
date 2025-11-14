// controllers/policyController.js
const Policy = require('../models/policyModel');

// Add a new policy
async function addPolicy(req, res) {
  const { clientId, policyNumber, type, premium, startDate, endDate } = req.body;
  try {
    const result = await Policy.addPolicy(clientId, policyNumber, type, premium, startDate, endDate);
    res.status(201).json({ message: 'Policy added successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Error adding policy.' });
  }
}

// List all policies
async function listPolicies(req, res) {
  try {
    const policies = await Policy.listPolicies();
    res.json(policies);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching policies.' });
  }
}

module.exports = { addPolicy, listPolicies };