const mongoose = require('mongoose');
const { Schema } = mongoose;

const UserSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true,   // Automatically trims whitespace
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,   // Converts the email to lowercase
        match: [/.+@.+\..+/, 'Invalid email format']   // Basic email validation
    },
    password: {
        type: String,
        required: true,
    }
});

// Export the model
const User = mongoose.model('User', UserSchema);
module.exports = User;
