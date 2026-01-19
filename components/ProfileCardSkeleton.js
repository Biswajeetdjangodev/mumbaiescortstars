"use client";

export function ProfileCardSkeleton() {
  return (
    <div className="bg-gray-900 text-white rounded-lg shadow-lg overflow-hidden relative animate-pulse">
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
  );
}
