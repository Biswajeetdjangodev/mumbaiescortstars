import { NextRequest, NextResponse } from 'next/server';
import ImageKit from 'imagekit';

if (!process.env.NEXT_PUBLIC_IMAGEKIT_PUBLIC_KEY || !process.env.IMAGEKIT_PRIVATE_KEY || !process.env.NEXT_PUBLIC_IMAGEKIT_URL_ENDPOINT) {
  throw new Error("ImageKit environment variables are not properly configured. Please check your .env.local file.");
}

const imagekit = new ImageKit({
  publicKey: process.env.NEXT_PUBLIC_IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.NEXT_PUBLIC_IMAGEKIT_URL_ENDPOINT,
});

export async function POST(request) {
  try {
    const formData = await request.formData();
    const files = formData.getAll('files');

    if (!files || files.length === 0) {
      return NextResponse.json({ error: 'No files provided' }, { status: 400 });
    }

    const uploadPromises = files.map(async (file) => {
      if (!(file instanceof File)) {
        throw new Error('Invalid file format');
      }

      // Convert file to buffer
      const bytes = await file.arrayBuffer();
      const buffer = Buffer.from(bytes);

      // Generate unique filename
      const fileName = `escort_${Date.now()}_${Math.random().toString(36).substring(7)}.${file.name.split('.').pop()}`;

      // Upload to ImageKit
      const result = await imagekit.upload({
        file: buffer,
        fileName: fileName,
        folder: '/escort-profiles/',
      });

      return {
        url: result.url,
        fileId: result.fileId,
        name: result.name,
      };
    });

    const uploadResults = await Promise.all(uploadPromises);

    return NextResponse.json({
      success: true,
      images: uploadResults,
    });

  } catch (error) {
    console.error('Upload error:', error);
    return NextResponse.json(
      { error: 'Failed to upload images', details: error.message },
      { status: 500 }
    );
  }
}
