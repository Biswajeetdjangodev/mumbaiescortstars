import { connectDB } from "@/lib/db";
import SEO from "@/lib/models/SEO";
import jwt from "jsonwebtoken";

export async function GET(req) {
  try {
    const { searchParams } = new URL(req.url);
    const page = searchParams.get('page');
    
    await connectDB();
    
    if (page) {
      // Get specific page SEO
      const seoData = await SEO.findOne({ page });
      if (!seoData) {
        return new Response(JSON.stringify({ error: "SEO data not found" }), { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response(JSON.stringify(seoData), { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      // Get all SEO data
      const seoData = await SEO.find();
      return new Response(JSON.stringify(seoData), { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("SEO GET error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function POST(req) {
  try {
    console.log("SEO POST request received");

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

    // Only allow admin to manage SEO
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

    // Handle different section types
    console.log("Processing section:", requestData.section);

    try {
      if (requestData.section === 'layout') {
        console.log("Handling layout section");
        // Handle layout metadata update
        const existingLayout = await SEO.findOne({ page: 'layout' });
        console.log("Existing layout found:", !!existingLayout);

        if (existingLayout) {
          existingLayout.seotitle = requestData.title;
          existingLayout.seodescription = requestData.description;
          await existingLayout.save();
          console.log("Layout updated successfully");
        } else {
          const newLayout = new SEO({
            page: 'layout',
            seotitle: requestData.title,
            seodescription: requestData.description,
          });
          await newLayout.save();
          console.log("Layout created successfully");
        }

        return new Response(JSON.stringify({ message: "Layout settings saved successfully" }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      } else {
        console.log("Handling regular SEO section");
        // Handle regular SEO content (homepage sections, social media, etc.)
        const {
          section,
          page,
          seotitle,
          seodescription,
          h1,
          content,
          metaKeywords,
          canonicalUrl,
          robots,
          ogTitle,
          ogDescription,
          ogImage,
          twitterTitle,
          twitterDescription,
          twitterImage,
          schema
        } = requestData;

        // Use section as page if page is not provided
        const pageKey = page || section;
        console.log("Using page key:", pageKey);

        try {
          // Check if SEO data already exists for this page/section
          const existingSEO = await SEO.findOne({ page: pageKey });
          console.log("Existing SEO found:", !!existingSEO);

          if (existingSEO) {
            console.log("Updating existing SEO");
            // Update existing SEO - only update fields that are provided
            if (seotitle !== undefined) existingSEO.seotitle = seotitle;
            if (seodescription !== undefined) existingSEO.seodescription = seodescription;
            if (h1 !== undefined) existingSEO.h1 = h1;
            if (content !== undefined) existingSEO.content = content;
            if (metaKeywords !== undefined) existingSEO.metaKeywords = metaKeywords;
            if (canonicalUrl !== undefined) existingSEO.canonicalUrl = canonicalUrl;
            if (robots !== undefined) existingSEO.robots = robots;
            if (ogTitle !== undefined) existingSEO.ogTitle = ogTitle;
            if (ogDescription !== undefined) existingSEO.ogDescription = ogDescription;
            if (ogImage !== undefined) existingSEO.ogImage = ogImage;
            if (twitterTitle !== undefined) existingSEO.twitterTitle = twitterTitle;
            if (twitterDescription !== undefined) existingSEO.twitterDescription = twitterDescription;
            if (twitterImage !== undefined) existingSEO.twitterImage = twitterImage;
            if (schema !== undefined) existingSEO.schema = schema;

            await existingSEO.save();
            console.log("SEO updated successfully");
            return new Response(JSON.stringify({ message: `${section || page} SEO updated successfully` }), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            });
          } else {
            console.log("Creating new SEO");
            // Create new SEO - only include fields that are provided
            const newSEOData = { page: pageKey };
            if (seotitle !== undefined && seotitle !== '') newSEOData.seotitle = seotitle;
            if (seodescription !== undefined && seodescription !== '') newSEOData.seodescription = seodescription;
            if (h1 !== undefined && h1 !== '') newSEOData.h1 = h1;
            if (content !== undefined && content !== '') newSEOData.content = content;
            if (metaKeywords !== undefined && Array.isArray(metaKeywords) && metaKeywords.length > 0) newSEOData.metaKeywords = metaKeywords;
            if (canonicalUrl !== undefined && canonicalUrl !== '') newSEOData.canonicalUrl = canonicalUrl;
            if (robots !== undefined && robots !== '') newSEOData.robots = robots;
            if (ogTitle !== undefined && ogTitle !== '') newSEOData.ogTitle = ogTitle;
            if (ogDescription !== undefined && ogDescription !== '') newSEOData.ogDescription = ogDescription;
            if (ogImage !== undefined && ogImage !== '') newSEOData.ogImage = ogImage;
            if (twitterTitle !== undefined && twitterTitle !== '') newSEOData.twitterTitle = twitterTitle;
            if (twitterDescription !== undefined && twitterDescription !== '') newSEOData.twitterDescription = twitterDescription;
            if (twitterImage !== undefined && twitterImage !== '') newSEOData.twitterImage = twitterImage;
            if (schema !== undefined && schema !== '') newSEOData.schema = schema;

            console.log("Creating SEO with data:", newSEOData);
            try {
              const newSEO = new SEO(newSEOData);
              await newSEO.save();
              console.log("SEO created successfully");
              return new Response(JSON.stringify({ message: `${section || page} SEO created successfully` }), {
                status: 201,
                headers: { 'Content-Type': 'application/json' }
              });
            } catch (validationError) {
              console.log("SEO validation error:", validationError.message);
              console.log("Validation details:", validationError.errors);
              return new Response(JSON.stringify({
                error: "Validation failed"
              }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
              });
            }
          }
        } catch (dbError) {
          console.log("Database operation failed:", dbError.message);
          console.log("Error details:", dbError);
          return new Response(JSON.stringify({
            error: "Database operation failed"
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }
    } catch (processingError) {
      console.log("Processing error:", processingError.message);
      console.log("Error details:", processingError);
      return new Response(JSON.stringify({
        error: "Processing failed"
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error("SEO POST error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
