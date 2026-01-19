import { NextResponse } from 'next/server';
import { connectDB } from '@/lib/db';
import Service from '@/lib/models/Service';

export async function GET() {
  try {
    await connectDB();

    // Aggregate unique tags from all services
    const tags = await Service.distinct('tags');

    // Flatten and remove duplicates
    const uniqueTags = [...new Set(tags.flat())];

    return NextResponse.json(uniqueTags);
  } catch (error) {
    console.error('Error fetching tags:', error);
    return NextResponse.json({ error: 'Failed to fetch tags' }, { status: 500 });
  }
}
