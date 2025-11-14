const express = require('express');
const { addPolicy, listPolicies } = require('../controllers/policyController');

const router = express.Router();

router.post('/add', addPolicy);
router.get('/list', listPolicies);

module.exports = router;