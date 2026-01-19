export default function OverviewTab({ services, onAddProfileClick }) {
  return (
    <div>
      <div className="mb-6 sm:mb-8">
        <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">Dashboard Overview</h2>
        <p className="text-purple-300 text-sm sm:text-base">Monitor your profile performance and engagement</p>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-6 sm:mb-8">
        <div className="bg-linear-to-br from-purple-800/50 to-purple-900/50 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-4 sm:p-6 shadow-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-purple-300 text-sm font-medium">Total Profiles</p>
              <p className="text-2xl sm:text-3xl font-bold text-white mt-2">{services.length}</p>
            </div>
            <div className="w-10 h-10 sm:w-12 sm:h-12 bg-purple-500/20 rounded-full flex items-center justify-center">
              <span className="text-xl sm:text-2xl">📋</span>
            </div>
          </div>
        </div>

        <div className="bg-linear-to-br from-green-800/50 to-green-900/50 backdrop-blur-sm border border-green-500/20 rounded-2xl p-4 sm:p-6 shadow-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-300 text-sm font-medium">Active Now</p>
              <p className="text-2xl sm:text-3xl font-bold text-white mt-2">
                {services.filter(s => s.availability === 'Available now').length}
              </p>
            </div>
            <div className="w-10 h-10 sm:w-12 sm:h-12 bg-green-500/20 rounded-full flex items-center justify-center">
              <span className="text-xl sm:text-2xl">✨</span>
            </div>
          </div>
        </div>

        <div className="bg-linear-to-br from-pink-800/50 to-pink-900/50 backdrop-blur-sm border border-pink-500/20 rounded-2xl p-4 sm:p-6 shadow-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-pink-300 text-sm font-medium">Profile Views</p>
              <p className="text-2xl sm:text-3xl font-bold text-white mt-2">1.2k</p>
            </div>
            <div className="w-10 h-10 sm:w-12 sm:h-12 bg-pink-500/20 rounded-full flex items-center justify-center">
              <span className="text-xl sm:text-2xl">👀</span>
            </div>
          </div>
        </div>

        <div className="bg-linear-to-br from-yellow-800/50 to-yellow-900/50 backdrop-blur-sm border border-yellow-500/20 rounded-2xl p-4 sm:p-6 shadow-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-yellow-300 text-sm font-medium">Favorites</p>
              <p className="text-2xl sm:text-3xl font-bold text-white mt-2">47</p>
            </div>
            <div className="w-10 h-10 sm:w-12 sm:h-12 bg-yellow-500/20 rounded-full flex items-center justify-center">
              <span className="text-xl sm:text-2xl">⭐</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-linear-to-r from-purple-800/30 to-pink-800/30 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-4 sm:p-6 mb-6 sm:mb-8 shadow-xl">
        <h2 className="text-lg sm:text-xl font-semibold text-white mb-4 flex items-center">
          <span className="mr-2">🚀</span>
          Quick Actions
        </h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          <button
            onClick={onAddProfileClick}
            className="bg-linear-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-3 sm:px-6 py-3 sm:py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-purple-500/25 flex flex-col sm:flex-row items-center justify-center space-y-1 sm:space-y-0 sm:space-x-2 text-sm"
          >
            <span className="text-lg sm:text-xl">➕</span>
            <span>New Profile</span>
          </button>
          <button
            onClick={() => setActiveTab('analytics')}
            className="bg-linear-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-3 sm:px-6 py-3 sm:py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-blue-500/25 flex flex-col sm:flex-row items-center justify-center space-y-1 sm:space-y-0 sm:space-x-2 text-sm"
          >
            <span className="text-lg sm:text-xl">📊</span>
            <span>Analytics</span>
          </button>
          <button className="bg-linear-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-3 sm:px-6 py-3 sm:py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-green-500/25 flex flex-col sm:flex-row items-center justify-center space-y-1 sm:space-y-0 sm:space-x-2 text-sm">
            <span className="text-lg sm:text-xl">💬</span>
            <span>Messages</span>
          </button>
          <button className="bg-linear-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white px-3 sm:px-6 py-3 sm:py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-orange-500/25 flex flex-col sm:flex-row items-center justify-center space-y-1 sm:space-y-0 sm:space-x-2 text-sm">
            <span className="text-lg sm:text-xl">⚙️</span>
            <span>Settings</span>
          </button>
        </div>
      </div>
    </div>
  );
}
