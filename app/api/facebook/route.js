import { connectDB } from "@/lib/db";
import Facebook from "@/lib/models/Facebook";
import jwt from "jsonwebtoken";

export async function GET(req) {
  try {
    await connectDB();

    const facebook = await Facebook.findOne();
    if (!facebook) {
      return new Response(JSON.stringify({
        ogTitle: '',
        ogDescription: '',
        ogImage: ''
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify(facebook), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("Facebook GET error:", error);
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

    const { ogTitle, ogDescription, ogImage } = await req.json();

    await connectDB();

    const existingFacebook = await Facebook.findOne();

    if (existingFacebook) {
      if (ogTitle !== undefined) existingFacebook.ogTitle = ogTitle;
      if (ogDescription !== undefined) existingFacebook.ogDescription = ogDescription;
      if (ogImage !== undefined) existingFacebook.ogImage = ogImage;
      await existingFacebook.save();
      return new Response(JSON.stringify({ message: "Facebook settings updated successfully" }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      const newFacebook = new Facebook({
        ogTitle: ogTitle || '',
        ogDescription: ogDescription || '',
        ogImage: ogImage || ''
      });
      await newFacebook.save();
      return new Response(JSON.stringify({ message: "Facebook settings created successfully" }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("Facebook POST error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
