import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";
import User from "@/lib/models/User";
import ProfileCard from "@/components/ProfileCard";
import Link from "next/link";

export default async function TagPage({ params }) {
  const { tag } = await params;

  let services = [];
  let error = null;

  try {
    await connectDB();

    // Find services that contain the tag
    services = await Service.find({
      tags: { $in: [tag] },
      status: 'Active',
      visibility: 'Visible'
    })
      .populate('createdBy', 'email')
      .sort({ createdAt: -1 })
      .lean();

    // Convert _id to string for client component compatibility
    const serializeObjectIds = (obj) => {
      if (obj && typeof obj === 'object') {
        if (obj._id && typeof obj._id.toString === 'function') {
          obj._id = obj._id.toString();
        }
        for (const key in obj) {
          if (obj.hasOwnProperty(key)) {
            serializeObjectIds(obj[key]);
          }
        }
      }
      return obj;
    };

    services = services.map(service => serializeObjectIds({ ...service }));
  } catch (err) {
    console.error('Error fetching profiles by tag:', err);
    error = err;
  }

  if (error) {
    return (
      <div className="text-white flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-[#bb86fc] mb-4">Error</h1>
          <p className="text-[#e0e0e0]">Failed to load profiles. Please try again later.</p>
          <Link
            href="/"
            className="inline-block mt-4 px-6 py-2 bg-[#bb86fc] text-white rounded-lg hover:bg-[#a855f7] transition-colors"
          >
            Back to Home
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="text-white">
      <div className="mx-auto px-2 sm:px-10 mb-8 sm:mb-0">
        <div className="mb-8">
          <Link
            href="/"
            className="text-[#bb86fc] hover:text-[#e0b3ff] transition-colors mb-4 inline-block"
          >
            ← Back to Home
          </Link>
          <h1 className="text-3xl font-bold text-[#bb86fc] mb-2">
            Profiles tagged with &apos;{tag}&apos;
          </h1>
          <p className="text-[#e0e0e0]">
            Found {services.length} profile{services.length !== 1 ? 's' : ''} with this tag
          </p>
        </div>

        {services.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-[#999999] text-lg">
              No profiles found with the tag &apos;{tag}&apos;
            </p>
            <Link
              href="/"
              className="inline-block mt-4 px-6 py-2 bg-[#bb86fc] text-white rounded-lg hover:bg-[#a855f7] transition-colors"
            >
              Browse All Profiles
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {services.map((service) => (
              <ProfileCard key={service._id} data={service} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// Generate metadata for SEO
export async function generateMetadata({ params }) {
  const { tag } = await params;
  return {
    title: `Profiles tagged with ${tag} | Escort Stars`,
    description: `Browse escort profiles tagged with ${tag}. Find the perfect companion for your needs.`,
    keywords: `${tag}, escort, profiles, companions`,
  };
}
