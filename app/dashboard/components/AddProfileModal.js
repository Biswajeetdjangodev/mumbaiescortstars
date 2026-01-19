import AdminProfileForm from '@/components/AdminProfileForm';

export default function AddProfileModal({ onClose, onProfileAdded }) {
  const handleClose = () => {
    console.log('Close button clicked');
    onClose();
  };

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) {
      handleClose();
    }
  };

  return (
    <div
      className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-2 sm:p-4"
      onClick={handleBackdropClick}
    >
      <div className="bg-linear-to-br from-gray-900 to-black border border-purple-500/20 rounded-2xl shadow-2xl w-full max-w-full sm:max-w-4xl max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-linear-to-r from-purple-900/80 to-pink-900/80 backdrop-blur-sm border-b border-purple-500/20 p-4 sm:p-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center">
              <span className="mr-2 sm:mr-3">✨</span>
              Create New Profile
            </h2>
            <button
              onClick={handleClose}
              className="w-8 h-8 sm:w-10 sm:h-10 bg-red-500/20 hover:bg-red-500/30 rounded-full flex items-center justify-center text-red-400 hover:text-red-300 transition-all duration-200"
              aria-label="Close modal"
            >
              ✕
            </button>
          </div>
        </div>
        <div className="p-4 sm:p-6">
          <AdminProfileForm
            onProfileAdded={onProfileAdded}
          />
        </div>
      </div>
    </div>
  );
}
