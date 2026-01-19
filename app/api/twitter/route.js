import { connectDB } from "@/lib/db";
import Twitter from "@/lib/models/Twitter";
import jwt from "jsonwebtoken";

export async function GET(req) {
  try {
    await connectDB();

    const twitter = await Twitter.findOne();
    if (!twitter) {
      return new Response(JSON.stringify({
        twitterTitle: '',
        twitterDescription: '',
        twitterImage: ''
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify(twitter), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("Twitter GET error:", error);
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

    const { twitterTitle, twitterDescription, twitterImage } = await req.json();

    await connectDB();

    const existingTwitter = await Twitter.findOne();

    if (existingTwitter) {
      if (twitterTitle !== undefined) existingTwitter.twitterTitle = twitterTitle;
      if (twitterDescription !== undefined) existingTwitter.twitterDescription = twitterDescription;
      if (twitterImage !== undefined) existingTwitter.twitterImage = twitterImage;
      await existingTwitter.save();
      return new Response(JSON.stringify({ message: "Twitter settings updated successfully" }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      const newTwitter = new Twitter({
        twitterTitle: twitterTitle || '',
        twitterDescription: twitterDescription || '',
        twitterImage: twitterImage || ''
      });
      await newTwitter.save();
      return new Response(JSON.stringify({ message: "Twitter settings created successfully" }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("Twitter POST error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
