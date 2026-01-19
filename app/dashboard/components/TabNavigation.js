export default function TabNavigation({ tabs, activeTab, onTabChange }) {
  return (
    <div className="bg-linear-to-r from-gray-900/50 to-black/50 backdrop-blur-sm border border-purple-500/20 rounded-2xl shadow-2xl mb-6 sm:mb-8">
      <div className="border-b border-purple-500/20">
        <nav className="flex flex-wrap px-2 py-2">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`flex-1 min-w-[120px] py-3 sm:py-4 px-3 sm:px-6 rounded-xl font-medium text-xs sm:text-sm flex items-center justify-center space-x-1 sm:space-x-2 transition-all duration-200 mx-1 mb-1 sm:mb-0 ${
                activeTab === tab.id
                  ? `bg-linear-to-r ${tab.color} text-white shadow-lg scale-105`
                  : 'text-gray-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="text-base sm:text-lg">{tab.icon}</span>
              <span className="hidden sm:inline">{tab.label}</span>
              <span className="sm:hidden">{tab.label.split(' ')[0]}</span>
            </button>
          ))}
        </nav>
      </div>
    </div>
  );
}
