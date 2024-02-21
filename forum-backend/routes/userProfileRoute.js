const express = require('express');
const router = express.Router();
const User = require('../models/UserDetails');
const authenticateToken = require('../middleware/authMiddleware');

// Route to get user profile
router.get('/', authenticateToken, async (req, res) => {
  try {
    // Retrieve user details from the authenticated request
    const user = req.user;
    // You can now use the user object to fetch additional profile information if needed
    // For example, const userProfile = await UserProfileModel.findOne({ user: user._id });
    return res.status(200).json({ user });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
router.patch('/update-picture', authenticateToken, async (req, res) => {
  const userId = req.user.id; // Retrieve user ID from authenticated request
  const pictureUrl = req.body.pictureUrl;

  try {
    // Update the user's profile picture
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profilePicture: pictureUrl },
      { new: true } // Return the updated document
    );

    if (!updatedUser) {
      // If user is not found, return a 404 Not Found response
      return res.status(404).json({ error: 'User not found' });
    }

    // Send a success response with the updated user object
    return res.status(200).json({ user: updatedUser });
  } catch (err) {
    // Handle errors
    console.error('Error updating profile picture:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
