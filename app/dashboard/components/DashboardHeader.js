export default function DashboardHeader({ user, onLogout }) {
  return (
    <div className="bg-black/30 backdrop-blur-sm border-b border-purple-500/20">
      <div className="max-w-7xl mx-auto px-2 sm:px-4 lg:px-8">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center py-4 sm:py-6 space-y-4 sm:space-y-0">
          <div className="flex items-center space-x-3 sm:space-x-4">
            <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-full bg-linear-to-r from-pink-500 to-purple-600 flex items-center justify-center shrink-0">
              <span className="text-white font-bold text-lg sm:text-xl">💎</span>
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold text-white">Escort Control Panel</h1>
              <p className="text-purple-300 text-sm sm:text-base">Professional Profile Management</p>
            </div>
          </div>
          <div className="flex flex-col sm:flex-row items-start sm:items-center space-y-2 sm:space-y-0 sm:space-x-4 w-full sm:w-auto">
            <div className="text-left sm:text-right">
              <p className="text-sm text-purple-300">Welcome, {user?.email?.split('@')[0]}</p>
              <p className="text-xs text-gray-400">Escort Professional</p>
            </div>
            <button
              onClick={onLogout}
              className="bg-linear-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 px-4 sm:px-6 py-2 rounded-full text-white font-medium transition-all duration-200 shadow-lg hover:shadow-red-500/25 text-sm sm:text-base"
            >
              Sign Out
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
