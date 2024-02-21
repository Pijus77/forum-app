const express = require('express');
const router = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/UserDetails');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validateLogin = require('../middleware/validateLogin');

const secretKey = '1';

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

// Route for user login with validation middleware
router.post('/login', validateLogin, (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res
        .status(401)
        .json({ message: 'Incorrect username or password' });
    }

    const token = jwt.sign(
      { username: user.username, isAdmin: user.isAdmin, id: user._id },
      secretKey,
      { expiresIn: '1h' }
    );
    return res.status(200).json({ token, user }); // Include user object in response
  })(req, res, next);
});

// Configure Passport local strategy for login
passport.use(
  new LocalStrategy(
    { usernameField: 'username', passwordField: 'password' },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });
        if (!user) {
          return done(null, false, { message: 'Incorrect username' });
        }
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
          return done(null, false, { message: 'Incorrect password' });
        }
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

module.exports = router;
