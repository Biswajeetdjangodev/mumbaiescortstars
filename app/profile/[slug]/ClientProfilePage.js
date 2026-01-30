'use client';

import { useState, lazy, Suspense } from 'react';
import Link from 'next/link';
import Image from 'next/image';

// Lazy load icons for better performance
const Heart = lazy(() => import('lucide-react').then(mod => ({ default: mod.Heart })));
const MessageCircle = lazy(() => import('lucide-react').then(mod => ({ default: mod.MessageCircle })));
const Phone = lazy(() => import('lucide-react').then(mod => ({ default: mod.Phone })));
const Clock = lazy(() => import('lucide-react').then(mod => ({ default: mod.Clock })));
const MapPin = lazy(() => import('lucide-react').then(mod => ({ default: mod.MapPin })));
const Star = lazy(() => import('lucide-react').then(mod => ({ default: mod.Star })));
const Camera = lazy(() => import('lucide-react').then(mod => ({ default: mod.Camera })));
const Home = lazy(() => import('lucide-react').then(mod => ({ default: mod.Home })));
const Calendar = lazy(() => import('lucide-react').then(mod => ({ default: mod.Calendar })));
const Plane = lazy(() => import('lucide-react').then(mod => ({ default: mod.Plane })));
const Utensils = lazy(() => import('lucide-react').then(mod => ({ default: mod.Utensils })));
const ChevronLeft = lazy(() => import('lucide-react').then(mod => ({ default: mod.ChevronLeft })));

function isBase64Image(src) {
  return src && src.startsWith('data:image/');
}

function ImageComponent({ src, alt, className, width, height, onClick, priority }) {
  if (!src) return null; // Do not render if src is empty or null
  if (isBase64Image(src)) {
    return (
      <Image
        width={width || 150}
        height={height || 150}
        src={src}
        alt={alt}
        className={className}
        onClick={onClick}
        priority={priority}
      />
    );
  }
  return (
    <Image
      src={src}
      alt={alt}
      width={width || 150}
      height={height || 150}
      className={className}
      onClick={onClick}
      priority={priority || width > 300} // Priority loading for larger images or when explicitly set
    />
  );
}

export default function ClientProfilePage({ profile }) {
  const [activeTab, setActiveTab] = useState('about');
  const [selectedImage, setSelectedImage] = useState(0);

  return (
    <div className="text-white">
      {/* Header */}
      <div className="bg-black/50 p-3 md:p-4">
        <div className="container mx-auto max-w-6xl">
          <Link className="flex items-center gap-2 md:gap-4" href="/">
            <div className="w-7 h-7 md:w-8 md:h-8 bg-pink-500 rounded flex items-center justify-center">
              <Suspense fallback={<div className="w-4 h-4 md:w-5 md:h-5" />}>
                <ChevronLeft className="w-4 h-4 md:w-5 md:h-5" />
              </Suspense>
            </div>
            <span className="text-xs md:text-sm opacity-75">BACK TO LIST</span>
          </Link>
        </div>
      </div>

      <div className="container mx-auto px-3 sm:px-4 py-4 md:py-6 max-w-6xl">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
          {/* Left Column - Images */}
          <div className="lg:col-span-1">
            <div className="lg:sticky lg:top-6">
              {/* Main Image */}
              <div className="relative mb-3 md:mb-4">
                <ImageComponent
                  src={profile?.gallery?.[selectedImage] || profile?.image}
                  alt={profile?.name || 'Profile'}
                  className="w-full h-64 sm:h-80 md:h-96 object-cover rounded-lg"
                  width={400}
                  height={400}
                  priority={true}
                />
                <div className="absolute top-2 md:top-4 left-2 md:left-4">
                  <span className="bg-green-500 text-[10px] md:text-xs px-2 py-1 rounded-full">{profile?.availability || 'ONLINE'}</span>
                </div>
                <div className="absolute bottom-2 md:bottom-4 right-2 md:right-4 flex gap-2">
                  <button className="bg-black/50 p-1.5 md:p-2 rounded-full hover:bg-black/70 transition-colors">
                    <Suspense fallback={<div className="w-4 h-4 md:w-5 md:h-5" />}>
                      <Heart className="w-4 h-4 md:w-5 md:h-5" />
                    </Suspense>
                  </button>
                  <button className="bg-black/50 p-1.5 md:p-2 rounded-full hover:bg-black/70 transition-colors">
                    <Suspense fallback={<div className="w-4 h-4 md:w-5 md:h-5" />}>
                      <Camera className="w-4 h-4 md:w-5 md:h-5" />
                    </Suspense>
                  </button>
                </div>
              </div>

              {/* Gallery - Responsive Grid */}
              {profile?.gallery && profile.gallery.length > 0 && (
                <div className="grid grid-cols-4 sm:grid-cols-5 lg:grid-cols-4 gap-1.5 md:gap-2 mb-4 md:mb-6">
                  {profile.gallery.map((img, index) => (
                    <ImageComponent
                      key={index}
                      src={img}
                      alt={`Gallery ${index + 1}`}
                      width={80}
                      height={80}
                      className={`w-full h-16 sm:h-20 object-cover rounded cursor-pointer transition-all ${
                        selectedImage === index ? 'ring-2 ring-pink-500' : 'hover:opacity-75'
                      }`}
                      onClick={() => setSelectedImage(index)}
                    />
                  ))}
                </div>
              )}

              {/* Quick Actions */}
              <div className="space-y-2 mb-6 lg:mb-0">
                <p className="text-xs text-gray-400 uppercase tracking-wide">QUICK ACTIONS</p>
                <div className="grid grid-cols-2 lg:grid-cols-1 gap-2">
                  <a href={`mailto:${(profile.agencyName && profile.agencyName.includes('@')) ? profile.agencyName : (profile.createdBy?.email || '')}`} className="w-full">
                    <button className="w-full bg-purple-600 hover:bg-purple-700 py-2.5 md:py-3 rounded-lg flex items-center justify-center gap-2 text-sm md:text-base transition-colors">
                      <Suspense fallback={<div className="w-4 h-4" />}>
                        <MessageCircle className="w-4 h-4" />
                      </Suspense>
                      <span className="hidden sm:inline">Send Message</span>
                      <span className="sm:hidden">Message</span>
                    </button>
                  </a>
                  <a href={`tel:${profile?.phone || ''}`} className="w-full">
                    <button className="w-full bg-green-600 hover:bg-green-700 py-2.5 md:py-3 rounded-lg flex items-center justify-center gap-2 text-sm md:text-base transition-colors">
                      <Suspense fallback={<div className="w-4 h-4" />}>
                        <Phone className="w-4 h-4" />
                      </Suspense>
                      <span className="hidden sm:inline">Call Now</span>
                      <span className="sm:hidden">Call</span>
                    </button>
                  </a>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column - Profile Info */}
          <div className="lg:col-span-2">
            {/* Profile Header */}
            <div className="mb-4 md:mb-6">
              <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-2 mb-2">
                <h1 className="text-2xl md:text-3xl font-bold">{profile?.name || 'Profile'}</h1>
                <div className="sm:text-right">
                  <div className="text-xl md:text-2xl font-bold text-pink-500">{profile?.price || 'N/A'}</div>
                  <div className="text-xs md:text-sm text-gray-400">per hour</div>
                </div>
              </div>
              <p className="text-sm md:text-base text-gray-300 mb-1">
                {profile?.nationality || 'Not specified'}
                {profile?.location && ` • ${profile.location}`}
              </p>
              <div className="flex flex-wrap items-center gap-3 md:gap-4 text-xs md:text-sm text-gray-400">
                <span className="flex items-center gap-1">
                  <Suspense fallback={<div className="w-3 h-3 md:w-4 md:h-4" />}>
                    <Star className="w-3 h-3 md:w-4 md:h-4 fill-yellow-500 text-yellow-500" />
                  </Suspense>
                  4.9 (127)
                </span>
                <span>Age {profile?.age || 'N/A'}</span>
                <span className="text-green-400">{profile?.availability || 'Available'}</span>
              </div>
            </div>

            {/* Tabs - Horizontal Scroll on Mobile */}
            <div className="border-b border-gray-700 mb-4 md:mb-6 overflow-x-auto">
              <nav className="flex space-x-4 md:space-x-8 min-w-max md:min-w-0">
                {['about', 'services',  'info'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`py-2 text-xs md:text-sm uppercase tracking-wide border-b-2 transition-colors whitespace-nowrap ${
                      activeTab === tab
                        ? 'border-pink-500 text-pink-500'
                        : 'border-transparent text-gray-400 hover:text-white'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            <div className="space-y-4 md:space-y-6">
              {activeTab === 'about' && (
                <div>
                  <h3 className="text-base md:text-lg font-semibold mb-2 md:mb-3">About Me</h3>
                  <div className="text-sm md:text-base text-gray-300 leading-relaxed space-y-3 md:space-y-4">
                    <p>{profile.description}</p>
                    <p>{profile.fullDescription}</p>
                  </div>
                </div>
              )}

              {activeTab === 'services' && (
                <div>
                  <h3 className="text-base md:text-lg font-semibold mb-2 md:mb-3">Services & Rates</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 md:gap-4">
                    {profile.services?.map((service, index) => {
                      const isString = typeof service === 'string';
                      const name = isString ? service : service.name;
                      const price = isString ? '' : service.price;

                      return (
                        <div key={index} className="bg-gray-800 p-3 md:p-4 rounded-lg flex justify-between items-center">
                          <div className="flex items-center gap-2 md:gap-3">
                            {/* <Suspense fallback={<div className="w-4 h-4 md:w-5 md:h-5" />}>
                              <IconComponent className="w-4 h-4 md:w-5 md:h-5 text-pink-500 shrink-0" />
                            </Suspense> */}
                            <span className="text-sm md:text-base capitalize">{name}</span>
                          </div>
                          {price && <span className="font-semibold text-pink-500 text-sm md:text-base whitespace-nowrap ml-2">{price}</span>}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* {activeTab === 'outcall' && (
                <div>
                  <h3 className="text-base md:text-lg font-semibold mb-2 md:mb-3">Outcall Information</h3>
                  <div className="bg-gray-800 p-3 md:p-4 rounded-lg">
                    <p className="text-sm md:text-base text-gray-300 mb-3 md:mb-4">Available for outcall services in {profile.location || 'the local area'}. Travel fees may apply for distances over 15 miles.</p>
                    <div className="space-y-2 text-sm md:text-base">
                      <div className="flex justify-between">
                        <span>Minimum booking:</span>
                        <span className="font-medium">2 hours</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Travel fee:</span>
                        <span className="font-medium">$50 (15+ miles)</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Advance notice:</span>
                        <span className="font-medium">2 hours preferred</span>
                      </div>
                    </div>
                  </div>
                </div>
              )} */}

              {activeTab === 'info' && (
                <div>
                  <h3 className="text-base md:text-lg font-semibold mb-2 md:mb-3">Physical Stats</h3>
                  <div className="grid grid-cols-2 gap-2 md:gap-4">
                    {Object.entries(profile.stats || {}).filter(([_, value]) => value).map(([key, value]) => (
                      <div key={key} className="bg-gray-800 p-2.5 md:p-3 rounded-lg">
                        <div className="text-[10px] md:text-xs text-gray-400 uppercase tracking-wide mb-1">
                          {key}
                        </div>
                        <div className="font-semibold text-sm md:text-base">{value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Contact Section */}
            <div className="mt-6 md:mt-8 bg-linear-to-r from-purple-600 to-pink-600 p-4 md:p-6 rounded-lg">
              <h3 className="text-base md:text-lg font-semibold mb-3 md:mb-4">Ready to Book?</h3>
              <div className="flex flex-col sm:flex-row gap-2 md:gap-4">
                <a href={`mailto:${(profile.agencyName && profile.agencyName.includes('@')) ? profile.agencyName : (profile.createdBy?.email || '')}`} className="flex-1">
                  <button className="w-full bg-white text-purple-600 font-semibold py-2.5 md:py-3 px-4 md:px-6 rounded-lg hover:bg-gray-100 transition-colors text-sm md:text-base">
                    Send Message
                  </button>
                </a>
                <a href={`tel:${profile?.phone || ''}`} className="flex-1">
                  <button className="w-full bg-black/20 border border-white/30 py-2.5 md:py-3 px-4 md:px-6 rounded-lg hover:bg-black/30 transition-colors text-sm md:text-base">
                    Call {profile?.phone || 'N/A'}
                  </button>
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
