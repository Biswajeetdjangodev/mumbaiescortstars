import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";
import ClientProfilePage from './ClientProfilePage';

async function getProfileData(slug) {
  try {
    await connectDB();
    
    // Query the Service model directly instead of calling an API
    const profile = await Service.findOne({ slug: slug }).lean();

    if (!profile) {
      return { profile: null, notFound: true };
    }

    // Serialize the data (convert ObjectIds and Dates to strings) for the client component
    const serializedProfile = JSON.parse(JSON.stringify(profile));
    return { profile: serializedProfile, notFound: false };
  } catch (error) {
    console.error('Error fetching profile:', error);
    return { profile: null, notFound: false, error: error.message };
  }
}

export default async function ProfilePage({ params }) {
  const { slug } = await params;

  // Fetch profile data on the server
  const result = await getProfileData(slug);

  if (result.notFound) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="text-white text-xl">Profile not found</div>
      </div>
    );
  }

  if (result.error) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="text-white text-xl">Unable to load profile. Please try again later.</div>
      </div>
    );
  }

  return <ClientProfilePage profile={result.profile} />;
}
