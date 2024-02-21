const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const User = require('../models/UserDetails');
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

// Configure JWT Strategy with hardcoded secret key
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: '1', // Hardcoded secret key
};

passport.use(
  new JWTStrategy(jwtOptions, async (jwtPayload, done) => {
    try {
      const user = await User.findById(jwtPayload.id);
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (error) {
      console.error(`Error in JWT strategy 1${error}`);
      return done(error, false);
    }
  })
);

// Local registration strategy
passport.use(
  'local',
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
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = new User({
          username,
          password: hashedPassword,
          isAdmin: req.body.isAdmin || false,
        });
        await newUser.save();
        return done(null, newUser);
      } catch (error) {
        console.error(`Error in JWT strategy 2${error}`);
        return done(error);
      }
    }
  )
);

// Local login strategy
passport.use(
  'local',
  new LocalStrategy(
    {
      usernameField: 'username',
      passwordField: 'password',
    },
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
        console.error(`Error in JWT strategy 3${error}`);
        return done(error);
      }
    }
  )
);

module.exports = passport;
