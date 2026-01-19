import AddProfileModal from './AddProfileModal';
import ProfileCard from './ProfileCard';

export default function ProfilesTab({ services, onAddProfile, refreshServices, showAddForm }) {
  return (
    <div>
      <div className="mb-6 sm:mb-8">
        <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">Profile Management</h2>
        <p className="text-pink-300 text-sm sm:text-base">Create and manage your professional profiles</p>
      </div>

      {/* Add Profile Modal */}
      {showAddForm && (
        <AddProfileModal
          onClose={() => onAddProfile(false)}
          onProfileAdded={() => {
            onAddProfile(false);
            refreshServices();
          }}
        />
      )}

      {/* Profiles Section */}
      <div className="bg-linear-to-br from-pink-800/20 to-purple-800/20 backdrop-blur-sm border border-purple-500/20 rounded-2xl shadow-xl">
        <div className="p-4 sm:p-6 border-b border-purple-500/20">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
            <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center">
              <span className="mr-2 sm:mr-3">💎</span>
              My Profiles
            </h2>
            <div className="flex items-center space-x-4">
              <div className="text-xs sm:text-sm text-purple-300">
                {services.length} {services.length === 1 ? 'profile' : 'profiles'} total
              </div>
              <button
                onClick={() => onAddProfile(true)}
                className="bg-linear-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-3 sm:px-4 py-2 rounded-lg font-medium transition-all duration-200 shadow-lg hover:shadow-purple-500/25 flex items-center space-x-2 text-sm"
              >
                <span>✨</span>
                <span>Add New</span>
              </button>
            </div>
          </div>
        </div>

        <div className="p-4 sm:p-6">
          {services.length === 0 ? (
            <div className="text-center py-12 sm:py-16">
              <div className="w-20 h-20 sm:w-24 sm:h-24 bg-linear-to-br from-purple-500/20 to-pink-500/20 rounded-full flex items-center justify-center mx-auto mb-4 sm:mb-6">
                <span className="text-3xl sm:text-4xl">🌟</span>
              </div>
              <h3 className="text-xl sm:text-2xl font-bold text-white mb-4">
                Ready to shine?
              </h3>
              <p className="text-purple-300 mb-6 sm:mb-8 max-w-md mx-auto text-sm sm:text-base">
                Create your first profile to start attracting clients and building your professional presence.
              </p>
              <button
                onClick={() => onAddProfile(true)}
                className="bg-linear-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-6 sm:px-8 py-3 sm:py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-purple-500/25 inline-flex items-center space-x-2 text-sm sm:text-base"
              >
                <span className="text-lg sm:text-xl">✨</span>
                <span>Create Your First Profile</span>
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
              {services.map((service) => (
                <ProfileCard key={service._id} service={service} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
