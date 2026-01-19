"use client";

export function HomePageSkeleton() {
  return (
    <div className="min-h-screen bg-gray-800 p-3 animate-pulse">
      <div className="mb-4">
        <div className="h-8 bg-gray-700 rounded w-1/2 mb-2"></div>
        <div className="h-4 bg-gray-700 rounded w-3/4"></div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 py-10 px-10">
        {Array.from({ length: 8 }).map((_, index) => (
          <div key={index} className="bg-gray-900 rounded-lg shadow-lg overflow-hidden relative">
            <div className="relative w-full aspect-[3/4] bg-gray-700"></div>
            <div className="p-4 space-y-3">
              <div className="h-6 bg-gray-700 rounded w-3/4"></div>
              <div className="h-3 bg-gray-700 rounded w-1/2"></div>
              <div className="h-4 bg-gray-700 rounded w-full"></div>
              <div className="h-4 bg-gray-700 rounded w-4/5"></div>
              <div className="flex items-center">
                <div className="w-4 h-4 bg-gray-700 rounded mr-2"></div>
                <div className="h-4 bg-gray-700 rounded w-20"></div>
              </div>
              <div className="flex items-center justify-between text-xs">
                <div className="h-3 bg-gray-700 rounded w-10"></div>
                <div className="h-3 bg-gray-700 rounded w-12"></div>
              </div>
            </div>
            <div className="absolute top-3 right-3 rounded-full h-8 w-8 bg-gray-700"></div>
          </div>
        ))}
      </div>
      <div className="p-3">
        <div className="h-4 bg-gray-700 rounded w-full mb-2"></div>
        <div className="h-4 bg-gray-700 rounded w-5/6"></div>
      </div>
    </div>
  );
}
