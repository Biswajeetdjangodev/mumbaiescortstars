export default function ProfileCard({ service }) {
  return (
    <div className="bg-linear-to-br from-purple-800/20 to-pink-800/20 backdrop-blur-sm border border-purple-500/20 rounded-xl p-4 sm:p-6 shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1">
      <div className="flex items-start justify-between mb-3 sm:mb-4">
        <div className="flex items-center space-x-2 sm:space-x-3 min-w-0 flex-1">
          <div className="w-10 h-10 sm:w-12 sm:h-12 bg-linear-to-r from-purple-500 to-pink-500 rounded-full flex items-center justify-center shrink-0">
            <span className="text-white font-bold text-sm sm:text-base">{service.name?.[0]?.toUpperCase()}</span>
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="text-base sm:text-lg font-bold text-white truncate">{service.name}</h3>
            <p className="text-purple-300 text-xs sm:text-sm truncate">{service.nationality || 'Not specified'}</p>
          </div>
        </div>
        <div className="flex items-center space-x-1 shrink-0">
          <span className={`w-2 h-2 sm:w-3 sm:h-3 rounded-full ${
            service.availability === 'Available now'
              ? 'bg-green-500 animate-pulse'
              : 'bg-gray-500'
          }`}></span>
          <span className={`text-xs font-medium ${
            service.availability === 'Available now'
              ? 'text-green-400'
              : 'text-gray-400'
          }`}>
            {service.availability === 'Available now' ? 'Online' : 'Offline'}
          </span>
        </div>
      </div>

      <div className="space-y-2 sm:space-y-3 mb-4 sm:mb-6">
        <div className="flex justify-between items-center">
          <span className="text-purple-300 text-xs sm:text-sm font-medium">Starting Price</span>
          <span className="text-white font-bold text-sm sm:text-base">{service.price}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-purple-300 text-xs sm:text-sm font-medium">Profile Views</span>
          <span className="text-white font-bold text-sm sm:text-base">127</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-purple-300 text-xs sm:text-sm font-medium">Favorites</span>
          <span className="text-yellow-400 font-bold text-sm sm:text-base">12 ⭐</span>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
        <button className="flex-1 bg-linear-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white px-3 sm:px-4 py-2 rounded-lg font-medium transition-all duration-200 text-xs sm:text-sm">
          ✏️ Edit
        </button>
        <button className="flex-1 bg-linear-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white px-3 sm:px-4 py-2 rounded-lg font-medium transition-all duration-200 text-xs sm:text-sm">
          👁️ View
        </button>
        <button className="bg-linear-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white px-3 sm:px-4 py-2 rounded-lg font-medium transition-all duration-200 text-xs sm:text-sm">
          🗑️
        </button>
      </div>
    </div>
  );
}
