import { connectDB } from '../lib/db.js';
import Service from '../lib/models/Service.js';

async function updateProfile() {
  const arg = process.argv[2];

  if (!arg) {
    console.error('Usage:');
    console.error('  node scripts/update-profile-status.js list       # List all profiles');
    console.error('  node scripts/update-profile-status.js all        # Activate ALL profiles');
    console.error('  node scripts/update-profile-status.js <slug>     # Activate specific profile');
    process.exit(1);
  }

  try {
    await connectDB();

    if (arg === 'list') {
      const profiles = await Service.find({}, 'slug status visibility name');
      console.log('--- All Profiles ---');
      if (profiles.length === 0) console.log('No profiles found in database.');
      profiles.forEach(p => {
        console.log(`Slug: ${p.slug.padEnd(20)} | Status: ${p.status} | Visibility: ${p.visibility}`);
      });
    } else if (arg === 'all') {
      const result = await Service.updateMany(
        {},
        { status: 'Active', visibility: 'Visible' }
      );
      console.log('Updated all profiles:', result);
    } else {
      const result = await Service.findOneAndUpdate(
        { slug: arg },
        { status: 'Active', visibility: 'Visible' },
        { new: true }
      );
      if (!result) {
        console.log(`Profile with slug "${arg}" NOT FOUND in database.`);
      } else {
        console.log('Profile updated:', result);
      }
    }
  } catch (error) {
    console.error('Error updating profile:', error);
  } finally {
    process.exit();
  }
}

updateProfile();
