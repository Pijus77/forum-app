const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const bcrypt = require('bcrypt');
const cors = require('cors'); // Import CORS module
const { validationResult } = require('express-validator');
const validateRegister = require('./middleware/validateRegister');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const userRoutes = require('./routes/userRoutes');
const authRoutes = require('./routes/authRoutes');
const userProfileRoute = require('./routes/userProfileRoute');
// const authenticateToken = require('./middleware/authMiddleware'); //
const app = express();
const authenticateToken = require('./config/jwt');

require('dotenv').config();

// Middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(cors()); // Use CORS middleware
app.options('*', cors()); // Enable pre-flight across-the-board

app.use(
  session({
    secret: '1',
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
const mongoUrl =
  'mongodb+srv://pijusj:pijusj@cluster0.2jih3jx.mongodb.net/node-auth';

mongoose
  .connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((error) => console.error('Error connecting to MongoDB:', error));

// User Model
const User = require('./models/UserDetails');

// Passport Configuration for registration
passport.use(
  'local-register',
  new LocalStrategy(
    {
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: true,
    },
    async (req, username, password, done) => {
      try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
          return done(null, false, { message: 'Username already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({
          username,
          password: hashedPassword,
          isAdmin: req.body.isAdmin === 'on',
        });
        return done(null, newUser);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users/profile', authenticateToken, userProfileRoute);
app.use('/api/users', authenticateToken, userRoutes);

// Handle registration endpoint
app.post('/register', validateRegister, (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  passport.authenticate('local-register', (err, user, info) => {
    if (err) {
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    if (!user) {
      return res.status(400).json({ message: 'Failed to register user' });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.status(201).json({ message: 'User registered successfully' });
    });
  })(req, res, next);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
