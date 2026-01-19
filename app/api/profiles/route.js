import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";

export async function GET(req) {
  try {
    await connectDB();
    const { searchParams } = new URL(req.url);
    const page = parseInt(searchParams.get('page')) || 1;
    const limit = parseInt(searchParams.get('limit')) || 10;
    const skip = (page - 1) * limit;

    const services = await Service.find()
      .skip(skip)
      .limit(limit)
      .populate('createdBy');
    
    return new Response(JSON.stringify(services), { status: 200 });
  } catch (err) {
    console.error("Error fetching services with pagination:", err);
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
