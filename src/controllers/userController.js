const bcrypt = require('bcrypt');
const User = require('../models/User');

// Controller function to get all users
exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        console.error('Error getting all users:', error);
        res.status(500).json({ error: 'An error occurred while getting all users' });
    }
};

// Controller function to get all active users
exports.getAllActiveUsers = async (req, res) => {
    try {
        const activeUsers = await User.find({ active: true });
        res.json(activeUsers);
    } catch (error) {
        console.error('Error getting all active users:', error);
        res.status(500).json({ error: 'An error occurred while getting all active users' });
    }
};

// Controller function to get all inactive users
exports.getAllInactiveUsers = async (req, res) => {
    try {
        const inactiveUsers = await User.find({ active: false });
        res.json(inactiveUsers);
    } catch (error) {
        console.error('Error getting all inactive users:', error);
        res.status(500).json({ error: 'An error occurred while getting all inactive users' });
    }
};

// Controller function to get a user by ID
exports.getUserById = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error getting user by ID:', error);
        res.status(500).json({ error: 'An error occurred while getting the user by ID' });
    }
};


// Controller function to get one user by username or email
exports.getUserByUsernameOrEmail = async (req, res) => {
    try {
        const { usernameOrEmail } = req.params;
        const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error getting user:', error);
        res.status(500).json({ error: 'An error occurred while getting the user' });
    }
};

// Controller function to update a user record
exports.updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;

        // Check if the password is being updated
        if (updates.password) {
            // Hash the new password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(updates.password, salt);
            updates.password = hashedPassword;
        }

        // Find the user by ID and update
        const updatedUser = await User.findByIdAndUpdate(id, updates, { new: true });

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(updatedUser);
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'An error occurred while updating the user' });
    }
};

// Controller function to delete a user record
exports.deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const deletedUser = await User.findByIdAndDelete(id);

        if (!deletedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'An error occurred while deleting the user' });
    }
};
