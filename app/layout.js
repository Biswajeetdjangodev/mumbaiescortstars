import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";
import ClientLayout from "@/components/ClientLayout";
import Footer from '@/components/Footer';
import { connectDB } from "@/lib/db";
import Layout from "@/lib/models/Layout";

// Force dynamic rendering to ensure fresh layout data on every request
export const dynamic = 'force-dynamic';

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

// Fetch layout metadata
async function fetchLayoutData() {
  try {
    await connectDB();
    const layout = await Layout.findOne().lean();
    return layout || { title: 'Escort App', description: 'Find your perfect companion' };
  } catch (error) {
    console.warn('Error fetching layout data:', error);
    return { title: 'Escort App', description: 'Find your perfect companion' };
  }
}

export async function generateMetadata() {
  const layoutData = await fetchLayoutData();

  return {
    title: layoutData.title || 'Escort App',
    description: layoutData.description || 'Find your perfect companion',
  };
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <ClientLayout>
          <Navbar />
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 sm:mt-20 mt-10 min-h-screen">
          {children}
          <Footer/>
          </div>
        </ClientLayout>
      </body>
    </html>
  );
}
