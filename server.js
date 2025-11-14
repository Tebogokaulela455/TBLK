// server.js
const app = require('./app');
const dotenv = require('dotenv');
const mysql = require('mysql2');

// Load environment variables
dotenv.config();

// Start the server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});