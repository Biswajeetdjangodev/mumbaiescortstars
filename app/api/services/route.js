import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";
import User from "@/lib/models/User";
import jwt from "jsonwebtoken";

function verifyUser(req) {
  const authHeader = req.headers.get("authorization");
  if (!authHeader) return null;
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded;
  } catch {
    return null;
  }
}

function verifyAdmin(req) {
  const user = verifyUser(req);
  return user && user.role === "admin" ? user : null;
}


export async function POST(req) {
  const user = verifyUser(req);
  if (!user || !["admin", "agency", "escort"].includes(user.role)) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403 });
  }

  await connectDB();
  const body = await req.json();
  
  // Get user details for agency name
  const userData = await User.findById(user.id);
  
  const service = new Service({
    ...body,
    createdBy: user.id,
    creatorRole: user.role,
    agencyName: userData.agencyName || userData.email // Use agency name or email as fallback
  });
  
  await service.save();
  return new Response(JSON.stringify(service), { status: 201 });
}

export async function PUT(req) {
  const user = verifyUser(req);
  if (!user || !["admin", "agency", "escort"].includes(user.role)) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403 });
  }

  await connectDB();
  const body = await req.json();
  
  // Check if user can edit this service
  const existingService = await Service.findById(body.id);
  if (!existingService) {
    return new Response(JSON.stringify({ error: "Service not found" }), { status: 404 });
  }
  
  // Only admin or the creator can edit
  if (user.role !== "admin" && existingService.createdBy.toString() !== user.id) {
    return new Response(JSON.stringify({ error: "Forbidden - You can only edit your own profiles" }), { status: 403 });
  }
  
  const updated = await Service.findByIdAndUpdate(body.id, body, { new: true });
  return new Response(JSON.stringify(updated), { status: 200 });
}

export async function DELETE(req) {
  const user = verifyUser(req);
  if (!user || !["admin", "agency", "escort"].includes(user.role)) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403 });
  }

  await connectDB();
  const { id } = await req.json();
  
  // Check if user can delete this service
  const existingService = await Service.findById(id);
  if (!existingService) {
    return new Response(JSON.stringify({ error: "Service not found" }), { status: 404 });
  }
  
  // Only admin or the creator can delete
  if (user.role !== "admin" && existingService.createdBy.toString() !== user.id) {
    return new Response(JSON.stringify({ error: "Forbidden - You can only delete your own profiles" }), { status: 403 });
  }
  
  await Service.findByIdAndDelete(id);
  return new Response(JSON.stringify({ message: "Profile deleted successfully" }), { status: 200 });
}


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
