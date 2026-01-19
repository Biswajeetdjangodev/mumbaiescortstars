import { connectDB } from "@/lib/db";
import User from "@/lib/models/User";
import jwt from "jsonwebtoken";

export async function GET(req) {
  try {
    const authHeader = req.headers.get("authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "No token provided" }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    console.log("Decoded JWT:", decoded); // Debug log

    // Only allow admin to view all users
    if (decoded.role !== 'admin') {
      console.log("User role:", decoded.role, "is not admin"); // Debug log
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await connectDB();
    const users = await User.find({}, { password: 0 }); // Exclude password field

    return new Response(JSON.stringify(users), { 
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error("Get users error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
