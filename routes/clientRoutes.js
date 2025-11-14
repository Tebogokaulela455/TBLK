const express = require('express');
const { addClient, listClients } = require('../controllers/clientController');

const router = express.Router();

router.post('/add', addClient);
router.get('/list', listClients);

module.exports = router;