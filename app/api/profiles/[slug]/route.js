import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";

export async function GET(req, { params }) {
  try {
    await connectDB();
    const { slug } = await params;

    // Query directly by slug for optimal performance
    const service = await Service.findOne({ slug })
      .populate('createdBy', 'email')
      .lean();

    if (!service) {
      return new Response(JSON.stringify({ error: "Profile not found" }), { status: 404 });
    }

    // Add cache headers
    return new Response(JSON.stringify(service), {
      status: 200,
      headers: {
        'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=600',
      },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
