import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";

export async function GET(req) {
  try {
    await connectDB();

    const url = new URL(req.url);
    const page = Math.max(1, parseInt(url.searchParams.get('page'), 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit'), 10) || 20));
    const skip = (page - 1) * limit;
    // Fetch only active services for homepage
    const total = await Service.countDocuments({ status: 'Active' });
    const services = await Service.find({ status: 'Active' })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalPages = Math.ceil(total / limit);
    const hasNext = page < totalPages;
    const hasPrev = page > 1;

    const pagination = {
      page,
      limit,
      total,
      totalPages,
      hasNext,
      hasPrev
    };

    return new Response(JSON.stringify({ services, pagination }), { status: 200 });
  } catch (error) {
    console.error('Error fetching services:', error);
    return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500 });
  }
}
