const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.get('/', userController.getAllUsers);
router.get('/active', userController.getAllActiveUsers);
router.get('/inactive', userController.getAllInactiveUsers);
router.get('/:usernameOrEmail', userController.getUserByUsernameOrEmail);
router.put('/:id', userController.updateUser);
router.delete('/:id', userController.deleteUser);

module.exports = router;