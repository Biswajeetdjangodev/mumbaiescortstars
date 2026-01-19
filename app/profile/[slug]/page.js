// Fetch profile data server-side
async function fetchProfileData(slug) {
  try {
    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
    const response = await fetch(`${baseUrl}/api/profiles/${slug}`, {
      cache: 'force-cache', // Cache the profile data
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return null; // Profile not found
      }
      throw new Error(`Failed to fetch profile: ${response.status}`);
    }

    const profile = await response.json();
    return profile;
  } catch (error) {
    console.error('Error fetching profile server-side:', error);
    return null;
  }
}

import ClientProfilePage from './ClientProfilePage';

export default async function ProfilePage({ params }) {
  const { slug } = await params;

  // Fetch profile data on the server
  const profile = await fetchProfileData(slug);
  console.log('Fetched profile data for slug', slug, profile);

  if (!profile) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="text-white text-xl">Profile not found</div>
      </div>
    );
  }

  return <ClientProfilePage profile={profile} />;
}
