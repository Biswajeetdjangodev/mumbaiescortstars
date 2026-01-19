export default function LoadingSpinner() {
  return (
    <div className="min-h-screen bg-linear-to-br from-purple-900 via-gray-900 to-black flex items-center justify-center px-4">
      <div className="flex flex-col items-center space-y-4">
        <div className="w-16 h-16 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin"></div>
        <p className="text-purple-300 text-lg font-medium text-center">Loading Escort Dashboard...</p>
      </div>
    </div>
  );
}
