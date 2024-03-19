const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    email: { type: String, unique: true, required: true }, // Add email field    
    roles: [{ type: String }],
    active: { type: Boolean, default: true } // New "active" field   
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

module.exports = User;