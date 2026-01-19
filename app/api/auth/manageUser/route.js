import { connectDB } from "@/lib/db";
import User from "@/lib/models/User";
import jwt from "jsonwebtoken";

export async function PATCH(req) {
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
    
    // Only allow admin to manage users
    if (decoded.role !== 'admin') {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { userId, action } = await req.json();
    await connectDB();

    const user = await User.findById(userId);
    if (!user) {
      return new Response(JSON.stringify({ error: "User not found" }), { 
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (action === 'block') {
      user.isBlocked = true;
      user.blockedAt = new Date();
    } else if (action === 'unblock') {
      user.isBlocked = false;
      user.blockedAt = null;
    } else {
      return new Response(JSON.stringify({ error: "Invalid action" }), { 
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await user.save();
    return new Response(JSON.stringify({ message: `User ${action}ed successfully` }), { 
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error("Manage user error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
