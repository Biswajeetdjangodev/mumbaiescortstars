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
    if (!token) {
      return new Response(JSON.stringify({ error: "Invalid token format" }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    await connectDB();
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return new Response(JSON.stringify({ error: "User not found" }), { 
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if user is blocked
    if (user.isBlocked) {
      return new Response(JSON.stringify({ error: "Account has been blocked" }), { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Return user data without password
    const userData = {
      id: user._id,
      email: user.email,
      role: user.role,
      phone: user.phone,
      agencyName: user.agencyName,
      isBlocked: user.isBlocked
    };

    return new Response(JSON.stringify(userData), { 
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error("Verify error:", error);
    return new Response(JSON.stringify({ error: "Invalid token" }), { 
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
