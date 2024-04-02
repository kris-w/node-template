const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    roles: [{ type: String }],
    active: { type: Boolean, default: true },
    resetToken: { type: String }, // New field for reset token
    resetTokenExpiration: { type: Date } // New field for reset token expiration
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

module.exports = User;
