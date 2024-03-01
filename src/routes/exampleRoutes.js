const express = require('express');
const router = express.Router();
const exampleController = require('../controllers/exampleController');

// Define routes
router.get('/', exampleController.exampleControllerFunction);

module.exports = router;
