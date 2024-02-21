// validateRegister.js
const expressValidator = require('express-validator');

const { check, validationResult } = expressValidator;

const validateRegister = [
  check('username')
    .notEmpty()
    .withMessage('Username is required')
    .isLength({
      min: 4,
      max: 20,
    })
    .withMessage('Username must be between 4 and 20 characters'),
  check('password')
    .notEmpty()
    .withMessage('Password is required')
    .isLength({
      min: 4,
      max: 20,
    })
    .withMessage('Password must be between 4 and 20 characters'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];

module.exports = validateRegister;
