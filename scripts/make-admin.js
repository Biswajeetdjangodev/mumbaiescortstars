const mongoose = require('mongoose');
const User = require('../lib/models/User');

async function makeAdmin() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/escort2');

    // Replace with your actual admin email
    const adminEmail = 'your-admin-email@example.com'; // Change this to your email

    const result = await User.updateOne(
      { email: adminEmail },
      { $set: { role: 'admin' } }
    );

    if (result.matchedCount === 0) {
      console.log('User not found with email:', adminEmail);
    } else if (result.modifiedCount === 0) {
      console.log('User already has admin role');
    } else {
      console.log('Successfully updated user to admin role');
    }

    await mongoose.disconnect();
    process.exit(0);
  } catch (error) {
    console.error('Error:', error);
    await mongoose.disconnect();
    process.exit(1);
  }
}

makeAdmin();
