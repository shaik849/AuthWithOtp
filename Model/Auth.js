const mongoose = require('mongoose');
const bcrypt = require('bcrypt')
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    maxLength: 100,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[A-Za-z0-9_!#$%&'*+\/=?`{|}~^.-]+@([\w-]+\.)+[\w-]{2,24}$/, 'Please fill a valid email address'],
  },
  password: {
    type: String,
    required: true,
    trim: true,
  },
  firstName: {
    type: String,
    required: false,
    maxLength: 40,
  },
  lastName: {
    type: String,
    required: false,
    maxLength: 40,
  },
  otp: {
    code: String,
    expiry: Date,
  }
}, { timestamps: true });

userSchema.pre('save', async function (next) {
    try {
      // Only hash the password if it's modified or new
      if (!this.isModified('password')) {
        return next();
      }
  
      // Generate a salt
      const salt = await bcrypt.genSalt(10);
  
      // Hash the password along with the new salt
      const hashedPassword = await bcrypt.hash(this.password, salt);
  
      // Replace the plain password with the hashed password
      this.password = hashedPassword;
  
      // Continue with the save operation
      next();
    } catch (error) {
      return next(error);
    }
  });

module.exports = mongoose.model('User', userSchema);
