export default function AnalyticsTab() {
  return (
    <div>
      <div className="mb-6 sm:mb-8">
        <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">Analytics & Insights</h2>
        <p className="text-blue-300 text-sm sm:text-base">Track your profile performance and engagement metrics</p>
      </div>

      <div className="bg-linear-to-br from-blue-800/20 to-purple-800/20 backdrop-blur-sm border border-blue-500/20 rounded-2xl p-6 sm:p-8 shadow-xl">
        <div className="text-center py-12 sm:py-16">
          <div className="w-20 h-20 sm:w-24 sm:h-24 bg-linear-to-br from-blue-500/20 to-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4 sm:mb-6">
            <span className="text-3xl sm:text-4xl">📈</span>
          </div>
          <h3 className="text-xl sm:text-2xl font-bold text-white mb-4">
            Analytics Coming Soon
          </h3>
          <p className="text-blue-300 max-w-md mx-auto text-sm sm:text-base">
            Detailed analytics and insights about your profile performance, visitor engagement, and booking trends will be available here.
          </p>
        </div>
      </div>
    </div>
  );
}
