const express = require('express');
const router = express.Router();
const passport = require('passport');
const User = require('../models/UserDetails');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const secretKey = '1'; // Replace with your actual secret key

// Route for user login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      console.error('Error:', err);
      return res
        .status(401)
        .json({ message: 'Incorrect username or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { username: user.username, isAdmin: user.isAdmin, id: user._id },
      secretKey,
      { expiresIn: '1h' }
    );

    console.log('Token generated:', token);
    return res.status(200).json({ token, user }); // Send the token and user info in the response
  })(req, res, next);
});
// Route for user registration
router.post('/register', async (req, res, next) => {
  try {
    const existingUser = await User.findOne({ username: req.body.username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const newUser = new User({
      username: req.body.username,
      password: hashedPassword,
      isAdmin: req.body.isAdmin || false,
    });

    await newUser.save();
    return res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
