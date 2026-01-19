import { connectDB } from "@/lib/db";
import HomepageTop from "@/lib/models/HomepageTop";
import jwt from "jsonwebtoken";

export async function GET(req) {
  try {
    await connectDB();

    const homepageTop = await HomepageTop.findOne();
    if (!homepageTop) {
      return new Response(JSON.stringify({
        h1: '',
        seodescription: ''
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify(homepageTop), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("Homepage Top GET error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function POST(req) {
  try {
    console.log("Homepage Top POST request received");

    const authHeader = req.headers.get("authorization");
    if (!authHeader) {
      console.log("No authorization header provided");
      return new Response(JSON.stringify({ error: "No token provided" }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const token = authHeader.split(" ")[1];
    console.log("Token extracted:", token ? "present" : "missing");

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log("JWT decoded successfully:", { role: decoded.role, email: decoded.email });
    } catch (jwtError) {
      console.log("JWT verification failed:", jwtError.message);
      return new Response(JSON.stringify({ error: "Invalid token" }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Only allow admin to manage homepage top
    if (decoded.role !== 'admin') {
      console.log("User role is not admin:", decoded.role);
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    let requestData;
    try {
      requestData = await req.json();
      console.log("Request data received:", requestData);
    } catch (jsonError) {
      console.log("Failed to parse JSON:", jsonError.message);
      return new Response(JSON.stringify({ error: "Invalid JSON data" }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      await connectDB();
      console.log("Database connected successfully");
    } catch (dbError) {
      console.log("Database connection failed:", dbError.message);
      return new Response(JSON.stringify({ error: "Database connection failed" }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const { h1, seodescription } = requestData;

      const existingHomepageTop = await HomepageTop.findOne();

      if (existingHomepageTop) {
        console.log("Updating existing homepage top");
        if (h1 !== undefined) existingHomepageTop.h1 = h1;
        if (seodescription !== undefined) existingHomepageTop.seodescription = seodescription;

        await existingHomepageTop.save();
        console.log("Homepage top updated successfully");
        return new Response(JSON.stringify({ message: "Homepage header updated successfully" }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      } else {
        console.log("Creating new homepage top");
        const newHomepageTop = new HomepageTop({
          h1: h1 || '',
          seodescription: seodescription || ''
        });

        await newHomepageTop.save();
        console.log("Homepage top created successfully");
        return new Response(JSON.stringify({ message: "Homepage header created successfully" }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    } catch (dbError) {
      console.log("Database operation failed:", dbError.message);
      console.log("Error details:", dbError);
      return new Response(JSON.stringify({
        error: "Database operation failed",
        details: dbError.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("Homepage Top POST error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
