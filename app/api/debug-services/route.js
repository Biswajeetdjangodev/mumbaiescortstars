import { connectDB } from "@/lib/db";
import Service from "@/lib/models/Service";
import { NextResponse } from "next/server";

export async function GET() {
  try {
    await connectDB();
    const services = await Service.find({}, 'name tags status visibility').lean();
    return NextResponse.json(services);
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
