import { connectDB } from "@/lib/db";
import Favorite from "@/lib/models/Favorite";
import User from "@/lib/models/User";
import jwt from "jsonwebtoken";

export async function POST(req) {
  try {
    await connectDB();
    
    // Check authentication
    const authHeader = req.headers.get("authorization");
    if (!authHeader) return new Response("Unauthorized", { status: 401 });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const body = await req.json();
    const { serviceId } = body;

    const existingFavorite = await Favorite.findOne({ user: decoded.id, service: serviceId });
    if (existingFavorite) {
      // Remove favorite
      await Favorite.findByIdAndDelete(existingFavorite._id);
      return new Response(JSON.stringify({ message: "Favorite removed" }), { status: 200 });
    } else {
      // Add favorite
      const favorite = new Favorite({ user: decoded.id, service: serviceId });
      await favorite.save();
      return new Response(JSON.stringify({ message: "Favorite added" }), { status: 201 });
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}

export async function GET(req) {
  try {
    await connectDB();
    const authHeader = req.headers.get("authorization");
    if (!authHeader) return new Response("Unauthorized", { status: 401 });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { searchParams } = new URL(req.url);
    const page = parseInt(searchParams.get('page')) || 1;
    const limit = parseInt(searchParams.get('limit')) || 10;
    const skip = (page - 1) * limit;
    
    const favorites = await Favorite.find({ user: decoded.id })
      .skip(skip)
      .limit(limit)
      .populate("service");
    return new Response(JSON.stringify(favorites), { status: 200 });
  } catch (err) {
    console.error("Error fetching favorites with pagination:", err);
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
