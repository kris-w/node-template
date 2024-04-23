const bcrypt = require('bcrypt');
const User = require('../models/User');
const promiseHandler = require("../middleware/promiseMiddleware");
const { logWithMetadata } = require('../middleware/loggingMiddleware');

const messages = {
  internalServerError: 'Internal Server Error',
  userNotFound: 'User not found',
  errorGettingAllUsers: 'An error occurred while getting all users',
  errorGettingAllActiveUsers: 'An error occurred while getting all active users',
  errorGettingAllInactiveUsers: 'An error occurred while getting all inactive users',
  errorGettingUserById: 'An error occurred while getting the user by ID',
  errorGettingUserByUsernameOrEmail: 'An error occurred while getting the user',
  errorUpdatingUser: 'An error occurred while updating the user',
  errorDeletingUser: 'An error occurred while deleting the user',
};

exports.getAllUsers = async (req, res) => {
  try {
    const usersPromise = User.find();
    const results = await promiseHandler(usersPromise, 5000);
    const users = results.success;
    
    res.json(users);
  } catch (error) {
    logWithMetadata(messages.errorGettingAllUsers, req, 'error', 'system');
    res.status(500).json({ error: messages.internalServerError });
  }
};

exports.getAllActiveUsers = async (req, res) => {
  try {
    const activeUsersPromise = User.find({ active: true });
    const results = await promiseHandler(activeUsersPromise, 5000);
    const activeUsers = results.success;
    
    res.json(activeUsers);
  } catch (error) {
    logWithMetadata(messages.errorGettingAllActiveUsers, req, 'error', 'system');
    res.status(500).json({ error: messages.internalServerError });
  }
};

exports.getAllInactiveUsers = async (req, res) => {
  try {
    const inactiveUsersPromise = User.find({ active: false });
    const results = await promiseHandler(inactiveUsersPromise, 5000);
    const inactiveUsers = results.success;
    
    res.json(inactiveUsers);
  } catch (error) {
    logWithMetadata(messages.errorGettingAllInactiveUsers, req, 'error', 'system');
    res.status(500).json({ error: messages.internalServerError });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const userPromise = User.findById(id);
    const results = await promiseHandler(userPromise, 5000);
    const user = results.success;

    if (!user) {
      logWithMetadata(messages.userNotFound, req, 'warn', 'user');
      return res.status(404).json({ error: messages.userNotFound });
    }

    res.json(user);
  } catch (error) {
    logWithMetadata(messages.errorGettingUserById, req, 'error', 'system');
    res.status(500).json({ error: messages.internalServerError });
  }
};

exports.getUserByUsernameOrEmail = async (req, res) => {
  try {
    const { usernameOrEmail } = req.params;
    const userPromise = User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    const results = await promiseHandler(userPromise, 5000);
    const user = results.success;

    if (!user) {
      logWithMetadata(messages.userNotFound, req, 'warn', 'user');
      return res.status(404).json({ error: messages.userNotFound });
    }

    res.json(user);
  } catch (error) {
    logWithMetadata(messages.errorGettingUserByUsernameOrEmail, req, 'error', 'system');
    res.status(500).json({ error: messages.internalServerError });
  }
};

exports.updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    let updates = req.body;

    // Check if the password is being updated
    if (updates.password) {
      // Hash the new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(updates.password, salt);
      updates.password = hashedPassword;
    }

    // If roles are sent as a comma-separated string, convert them to an array
    if (typeof updates.roles === 'string') {
      updates.roles = updates.roles.split(',');
    }

    // Find the user by ID and update
    const updatedUserPromise = User.findByIdAndUpdate(id, updates, { new: true });
    const results = await promiseHandler(updatedUserPromise, 5000);
    const updatedUser = results.success;

    if (!updatedUser) {
      logWithMetadata(messages.userNotFound, req, 'warn', 'user');
      return res.status(404).json({ error: messages.userNotFound });
    }

    res.json(updatedUser);
  } catch (error) {
    logWithMetadata(messages.errorUpdatingUser, req, 'error', 'system');
    res.status(500).json({ error: messages.internalServerError });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    const deletedUserPromise = User.findByIdAndDelete(id);
    const results = await promiseHandler(deletedUserPromise, 5000);

    if (!results.success) {
      logWithMetadata(messages.userNotFound, req, 'warn', 'user');
      return res.status(404).json({ error: messages.userNotFound });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    logWithMetadata(messages.errorDeletingUser, req, 'error', 'system');
    res.status(500).json({ error: messages.internalServerError });
  }
};
