import { connectDB } from "@/lib/db";
import Meta from "@/lib/models/Meta";
import jwt from "jsonwebtoken";

export const runtime = 'nodejs';

export async function GET(req) {
  try {
    console.log("Meta GET: Connecting to DB...");
    await connectDB();
    console.log("Meta GET: DB Connected.");

    console.log("Meta GET: Querying for data...");
    const meta = await Meta.findOne().lean();
    console.log("Meta GET: Query successful.");

    if (!meta) {
      console.log("Meta GET: No data found, returning default.");
      return new Response(JSON.stringify({
        seotitle: '',
        seodescription: '',
        metaKeywords: [],
        canonicalUrl: '',
        robots: 'index, follow'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    console.log("Meta GET: Data found, returning.");
    return new Response(JSON.stringify(meta), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("Meta GET error:", error);
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

    const { seotitle, seodescription, metaKeywords, canonicalUrl, robots } = await req.json();

    await connectDB();

    const existingMeta = await Meta.findOne();

    if (existingMeta) {
      if (seotitle !== undefined) existingMeta.seotitle = seotitle;
      if (seodescription !== undefined) existingMeta.seodescription = seodescription;
      if (metaKeywords !== undefined) existingMeta.metaKeywords = metaKeywords;
      if (canonicalUrl !== undefined) existingMeta.canonicalUrl = canonicalUrl;
      if (robots !== undefined) existingMeta.robots = robots;
      await existingMeta.save();
      return new Response(JSON.stringify({ message: "Meta settings updated successfully" }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      const newMeta = new Meta({
        seotitle: seotitle || '',
        seodescription: seodescription || '',
        metaKeywords: metaKeywords || [],
        canonicalUrl: canonicalUrl || '',
        robots: robots || 'index, follow'
      });
      await newMeta.save();
      return new Response(JSON.stringify({ message: "Meta settings created successfully" }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("Meta POST error:", error?.stack || error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
