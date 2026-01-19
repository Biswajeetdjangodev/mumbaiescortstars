import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";
import User from "@/lib/models/User";
import jwt from "jsonwebtoken";
import { revalidateTag, revalidatePath } from 'next/cache';

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

export async function GET(req) {
  await connectDB();

  const url = new URL(req.url);
  const tag = url.searchParams.get('tag');
  const page = parseInt(url.searchParams.get('page')) || 1;
  const limit = parseInt(url.searchParams.get('limit')) || 20; // Default 20 profiles per page
  const skip = (page - 1) * limit;

  // Check if request includes auth header for filtered results
  const user = verifyUser(req);
  let query = {};

  // Add tag filter if provided
  if (tag) {
    query.tags = { $in: [tag] };
  }

  let services;
  let totalCount;

  if (user) {
    // Return filtered results based on role with pagination
    let baseQuery;
    if (user.role === "admin") {
      // Admin sees all profiles
      baseQuery = Service.find(query);
    } else if (user.role === "agency") {
      // Agency users see only their own profiles
      baseQuery = Service.find({ ...query, createdBy: user.id });
    } else if (user.role === "escort") {
      // Escort users see only their own profiles
      baseQuery = Service.find({ ...query, createdBy: user.id });
    } else {
      // Other roles see all public profiles (no filtering)
      baseQuery = Service.find(query);
    }

    // Get total count for pagination
    totalCount = await Service.countDocuments(baseQuery.getQuery());

    // Apply pagination and populate
    services = await baseQuery
      .select('-fullDescription -internalNotes -reasonForStatusChange') // Exclude large fields for list view
      .populate('createdBy', 'email agencyName')
      .sort({ createdAt: -1 }) // Sort by newest first
      .skip(skip)
      .limit(limit)
      .lean();
  } else {
    // Public access - show all profiles with pagination, exclude internal fields
    totalCount = await Service.countDocuments(query);

    services = await Service.find(query)
      .select('-fullDescription -internalNotes -reasonForStatusChange')
      .sort({ createdAt: -1 }) // Sort by newest first
      .skip(skip)
      .limit(limit)
      .lean();
  }

  return new Response(JSON.stringify({
    services,
    pagination: {
      page,
      limit,
      total: totalCount,
      totalPages: Math.ceil(totalCount / limit),
      hasNext: page * limit < totalCount,
      hasPrev: page > 1
    }
  }), {
    status: 200,
  });
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

  const { tags, services, ...rest } = body;

  const service = new Service({
    ...rest,
    tags: tags || [],
    services: services || [],
    createdBy: user.id,
    creatorRole: user.role,
    agencyName: userData.agencyName || userData.email // Use agency name or email as fallback
  });
  
  await service.save();

  // Invalidate cache for services and homepage
  revalidateTag('services');
  revalidatePath('/');

  return new Response(JSON.stringify(service), { status: 201 });
}

export async function PUT(req) {
  const user = verifyUser(req);
  if (!user || !["admin", "agency", "escort"].includes(user.role)) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403 });
  }

  await connectDB();
  const body = await req.json();

  console.log('PUT request body:', body);
  console.log('PUT body.tags:', body.tags, 'type:', typeof body.tags, 'isArray:', Array.isArray(body.tags));
  console.log('PUT body.services:', body.services, 'type:', typeof body.services, 'isArray:', Array.isArray(body.services));

  // Check if user can edit this service
  const existingService = await Service.findById(body.id);
  if (!existingService) {
    return new Response(JSON.stringify({ error: "Service not found" }), { status: 404 });
  }

  // Only admin or the creator can edit
  if (user.role !== "admin" && existingService.createdBy.toString() !== user.id) {
    return new Response(JSON.stringify({ error: "Forbidden - You can only edit your own profiles" }), { status: 403 });
  }

  const { id, tags, services, ...rest } = body;
  const updateData = { ...rest };

  console.log('PUT updateData before array handling:', updateData);

  // Update tags if they are explicitly provided in the request
  if (Array.isArray(tags)) {
    updateData.tags = tags;
    console.log('PUT setting tags:', tags);
  }

  // Update services if they are explicitly provided in the request
  if (Array.isArray(services)) {
    updateData.services = services;
    console.log('PUT setting services:', services);
  }

  console.log('PUT final updateData:', updateData);

  try {
    const updated = await Service.findByIdAndUpdate(id, updateData, { new: true });
    console.log('PUT update successful:', updated);

    // Invalidate cache for services
    revalidateTag('services');

    return new Response(JSON.stringify(updated), { status: 200 });
  } catch (error) {
    console.error('PUT update error:', error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
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
