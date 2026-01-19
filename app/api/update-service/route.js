import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";
import { NextResponse } from "next/server";

export async function POST(request) {
  try {
    await connectDB();
    const { name } = await request.json();
    const service = await Service.findOne({ name: name });

    if (!service) {
      return NextResponse.json({ error: "Service not found" }, { status: 404 });
    }

    service.status = "Active";
    service.visibility = "Visible";
    await service.save();

    return NextResponse.json(service);
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
