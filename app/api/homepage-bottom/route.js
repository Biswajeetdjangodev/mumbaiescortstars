import { connectDB } from "@/lib/db";
import HomepageBottom from "@/lib/models/HomepageBottom";
import jwt from "jsonwebtoken";

export async function GET(req) {
  try {
    await connectDB();

    const homepageBottom = await HomepageBottom.findOne();
    if (!homepageBottom) {
      return new Response(JSON.stringify({
        content: ''
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify(homepageBottom), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("Homepage Bottom GET error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function POST(req) {
  try {
    console.log("Homepage Bottom POST request received");

    const authHeader = req.headers.get("authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "No token provided" }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtError) {
      return new Response(JSON.stringify({ error: "Invalid token" }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (decoded.role !== 'admin') {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { content } = await req.json();

    await connectDB();

    const existingHomepageBottom = await HomepageBottom.findOne();

    if (existingHomepageBottom) {
      if (content !== undefined) existingHomepageBottom.content = content;
      await existingHomepageBottom.save();
      return new Response(JSON.stringify({ message: "Homepage footer updated successfully" }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      const newHomepageBottom = new HomepageBottom({
        content: content || ''
      });
      await newHomepageBottom.save();
      return new Response(JSON.stringify({ message: "Homepage footer created successfully" }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("Homepage Bottom POST error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
