const mongoose = require('mongoose');

const UserDetailSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    profilePicture: {
      type: String,
      default:
        'https://fastly.picsum.photos/id/890/200/300.jpg?hmac=INUR_Xore_GSEXH-cqmLjy_lJcK8tslVvXwwac-9o8M',
    }, // Set default profile picture
    discussions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Discussion' }],
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
  },
  {
    collection: 'UserInfo',
  }
);

module.exports = mongoose.model('User', UserDetailSchema);
