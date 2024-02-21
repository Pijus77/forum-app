// routes/login.js
const express = require('express');
const router = express.Router();
const User = require('../models/UserDetails');
const validateLogin = require('../middleware/validateLogin');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

router.post('/', validateLogin, async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ error: 'User not found' });
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(401).json({ error: 'Invalid password' });
  const token = jwt.sign(
    { id: user._id, isAdmin: user.isAdmin, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  res.json({ token });
});

module.exports = router;
