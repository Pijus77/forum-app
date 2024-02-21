const { error } = require('console');
const jwt = require('jsonwebtoken');
const secretKey = '1';

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization.split(' ')[1]; // Bearer <token>
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Token missing' });
  }

  jwt.verify(token, secretKey, (err, decodedToken) => {
    if (err) {
      console.error(err);
      return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
    req.user = decodedToken; // Attach decoded token payload to the request
    next(); // Proceed to the next middleware
  });
};

module.exports = authenticateToken;
