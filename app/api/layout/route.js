import { connectDB } from "@/lib/db";
import Layout from "@/lib/models/Layout";
import jwt from "jsonwebtoken";

export const runtime = 'nodejs';

export async function GET(req) {
  try {
    console.log("Layout GET: Connecting to DB...");
    await connectDB();
    console.log("Layout GET: DB Connected.");

    console.log("Layout GET: Querying for data...");
    const layout = await Layout.findOne().lean();
    console.log("Layout GET: Query successful.");

    if (!layout) {
      console.log("Layout GET: No data found, returning default.");
      return new Response(JSON.stringify({
        title: '',
        description: ''
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    console.log("Layout GET: Data found, returning.");
    return new Response(JSON.stringify(layout), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("Layout GET error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function POST(req) {
  try {
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

    const { title, description } = await req.json();

    await connectDB();

    const existingLayout = await Layout.findOne();

    if (existingLayout) {
      if (title !== undefined) existingLayout.title = title;
      if (description !== undefined) existingLayout.description = description;
      await existingLayout.save();
      return new Response(JSON.stringify({ message: "Layout settings updated successfully" }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      const newLayout = new Layout({
        title: title || '',
        description: description || ''
      });
      await newLayout.save();
      return new Response(JSON.stringify({ message: "Layout settings created successfully" }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("Layout POST error:", error?.stack || error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
