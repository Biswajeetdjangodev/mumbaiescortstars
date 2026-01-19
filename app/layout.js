import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";
import ClientLayout from "@/components/ClientLayout";
import Footer from '@/components/Footer';

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
    const response = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'}/api/layout`, {
      cache: 'no-store',
    });

    if (!response.ok) {
      console.warn('Failed to fetch layout data:', response.status);
      return { title: 'Escort App', description: 'Find your perfect companion' };
    }

    return await response.json();
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
