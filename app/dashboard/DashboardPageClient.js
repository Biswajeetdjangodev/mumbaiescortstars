'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useDispatch, useSelector } from 'react-redux';
import { fetchProfiles } from '../../lib/slices/profileSlice';
import AdminProfileForm from '@/components/AdminProfileForm';

export default function DashboardPageClient({ initialServices, initialUser }) {
  const dispatch = useDispatch();
  const { profiles: services, loading } = useSelector((state) => state.profile);
  const [user, setUser] = useState(initialUser || null);
  const [showAddForm, setShowAddForm] = useState(false);
  const router = useRouter();

  // Use server-fetched data initially, then switch to Redux state when client-side data is loaded
  const displayServices = services.length > 0 ? services : initialServices;

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }

    // Verify user role
    fetch('/api/auth/verify', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(res => {
      if (!res.ok) {
        throw new Error('Unauthorized');
      }
      return res.json();
    })
    .then(userData => {
      if (userData.role !== 'admin') {
        router.push('/');
        return;
      }
      setUser(userData);
      dispatch(fetchProfiles());
    })
    .catch(err => {
      console.error('Error:', err);
      router.push('/login');
    });
  }, [router, dispatch]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  if (loading && !initialServices.length) {
    return (
      <div className="min-h-screen bg-gray-900 flex justify-center items-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <div className="bg-black/50 p-4 flex justify-between items-center">
        <h1 className="text-2xl font-bold">Admin Dashboard</h1>
        <div className="flex items-center gap-4">
          <span>Welcome, {user?.email}</span>
          <button
            onClick={handleLogout}
            className="bg-red-600 px-4 py-2 rounded text-sm hover:bg-red-700"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-lg font-semibold mb-2">Total Profiles</h3>
            <p className="text-3xl font-bold text-pink-500">{displayServices.length}</p>
          </div>
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-lg font-semibold mb-2">Active Profiles</h3>
            <p className="text-3xl font-bold text-green-500">
              {displayServices.filter(s => s.availability === 'Available now').length}
            </p>
          </div>
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-lg font-semibold mb-2">Admin Access</h3>
            <p className="text-sm text-gray-400">Full administrative privileges</p>
          </div>
        </div>

        {/* Add Profile Form */}
        {showAddForm && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-semibold">Add New Profile</h2>
              <button
                onClick={() => setShowAddForm(false)}
                className="bg-gray-600 px-3 py-1 rounded text-sm hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
            <AdminProfileForm
              onProfileAdded={() => {
                setShowAddForm(false);
                // Refresh the services list
                fetch('/api/services')
                  .then(res => res.json())
                  .then(data => dispatch(fetchProfiles()));
              }}
            />
          </div>
        )}

        {/* Services List */}
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-semibold">Manage Profiles</h2>
            <button
              onClick={() => setShowAddForm(true)}
              className="bg-pink-600 px-4 py-2 rounded text-sm hover:bg-pink-700"
            >
              Add New Profile
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3">Name</th>
                  <th className="text-left py-3">Nationality</th>
                  <th className="text-left py-3">Price</th>
                  <th className="text-left py-3">Status</th>
                  <th className="text-left py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {displayServices.map((service) => (
                  <tr key={service._id} className="border-b border-gray-700">
                    <td className="py-3">{service.name}</td>
                    <td className="py-3">{service.nationality || 'N/A'}</td>
                    <td className="py-3">{service.price}</td>
                    <td className="py-3">
                      <span className={`px-2 py-1 rounded-full text-xs ${
                        service.availability === 'Available now'
                          ? 'bg-green-500 text-green-900'
                          : 'bg-gray-500 text-gray-900'
                      }`}>
                        {service.availability || 'Unknown'}
                      </span>
                    </td>
                    <td className="py-3">
                      <div className="flex gap-2">
                        <button className="bg-blue-600 px-3 py-1 rounded text-xs hover:bg-blue-700">
                          Edit
                        </button>
                        <button className="bg-red-600 px-3 py-1 rounded text-xs hover:bg-red-700">
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
