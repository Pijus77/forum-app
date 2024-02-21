const passport = require('passport');
const User = require('../models/UserDetails');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

// Configure JWT Strategy with your secret key
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: '1', // Replace '1' with your actual secret key
};

// Define JWT Strategy
const jwtStrategy = new JwtStrategy(jwtOptions, async (jwtPayload, done) => {
  console.log(jwtPayload);
  try {
    // Find user by ID extracted from JWT payload
    const user = await User.findById(jwtPayload.id);
    if (user) {
      // If user exists, authentication is successful
      return done(null, user);
    } else {
      // If user does not exist, authentication fails
      return done(null, false);
    }
  } catch (error) {
    // If an error occurs during authentication, pass the error to the done callback
    console.error(`Error in JWT strategy  authMiddleware${error}`);
    return done(error, false);
  }
});

// Register JWT Strategy with Passport
passport.use(jwtStrategy);

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  // Use Passport to authenticate the token
  passport.authenticate('jwt', { session: false }, async (err, user, info) => {
    try {
      if (err || !user) {
        // If authentication fails, send unauthorized error response
        return res.status(401).json({ error: 'Unauthorized' });
      }
      // If authentication succeeds, set the authenticated user in the request object and proceed to the next middleware
      req.user = user;
      return next();
    } catch (error) {
      // If an error occurs during authentication, send internal server error response
      console.error('Error authenticating token:', error);
      return res
        .status(500)
        .json({ error: 'Unauthorized: Failed to authenticate token' });
    }
  })(req, res, next);
};

module.exports = authenticateToken;
