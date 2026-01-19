'use client'
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import AdminProfileForm from '@/components/AdminProfileForm';
import { PencilIcon, TrashIcon, PlusIcon, XIcon } from 'lucide-react';
import Image from 'next/image';

export default function ProfileManagement() {
  const [user, setUser] = useState(null);
  const [services, setServices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [editingService, setEditingService] = useState(null);
  const [actionLoading, setActionLoading] = useState({});
  const [searchTerm, setSearchTerm] = useState('');
  const router = useRouter();

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

      // Fetch services
      return fetch('/api/services');
    })
    .then(res => res.json())
    .then(servicesData => {
      // Handle both paginated response format and direct array format
      const servicesArray = servicesData.services || servicesData;
      setServices(Array.isArray(servicesArray) ? servicesArray : []);
      setLoading(false);
    })
    .catch(err => {
      console.error('Error:', err);
      router.push('/login');
    });
  }, [router]);

  const fetchServices = async () => {
    try {
      const response = await fetch('/api/services');
      if (response.ok) {
        const data = await response.json();
        // Handle both paginated response format and direct array format
        const servicesArray = data.services || data;
        setServices(Array.isArray(servicesArray) ? servicesArray : []);
      }
    } catch (error) {
      console.error('Error fetching services:', error);
    }
  };

  const handleDelete = async (serviceId) => {
    if (!confirm('Are you sure you want to delete this profile?')) return;

    setActionLoading(prev => ({ ...prev, [serviceId]: true }));
    const token = localStorage.getItem('token');

    try {
      const response = await fetch('/api/services', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ id: serviceId })
      });

      if (response.ok) {
        alert('Profile deleted successfully!');
        await fetchServices();
      } else {
        alert('Failed to delete profile');
      }
    } catch (error) {
      console.error('Error deleting profile:', error);
      alert('Error deleting profile');
    } finally {
      setActionLoading(prev => ({ ...prev, [serviceId]: false }));
    }
  };

  const handleEdit = (service) => {
    setEditingService(service);
    setShowAddForm(true);
  };

  const handleProfileAdded = async () => {
    setShowAddForm(false);
    setEditingService(null);
    await fetchServices();
  };

  const filteredServices = services.filter(service =>
    service.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    service.nationality?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="min-h-screen flex justify-center items-center">
        <div className="flex flex-col items-center space-y-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-pink-500"></div>
          <p className="text-white text-lg sm:text-xl">Loading profiles...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <div className="mb-6 sm:mb-8">
        <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">Profile Management</h2>
        <p className="text-sm sm:text-base text-gray-300">All the profiles there are managed here</p>
      </div>

      <div className="max-w-7xl mx-auto px-0 sm:px-6 lg:px-8 py-4 sm:py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6 mb-6 sm:mb-8">
          <div className="bg-gray-800 p-4 sm:p-6 rounded-lg shadow-lg border border-gray-700">
            <h3 className="text-sm sm:text-lg font-semibold mb-2 text-gray-300">Total Profiles</h3>
            <p className="text-2xl sm:text-3xl font-bold text-pink-500">{services.length}</p>
          </div>
          <div className="bg-gray-800 p-4 sm:p-6 rounded-lg shadow-lg border border-gray-700">
            <h3 className="text-sm sm:text-lg font-semibold mb-2 text-gray-300">Active Profiles</h3>
            <p className="text-2xl sm:text-3xl font-bold text-green-500">
              {services.filter(s => s.availability === 'Available now').length}
            </p>
          </div>
          <div className="bg-gray-800 p-4 sm:p-6 rounded-lg shadow-lg border border-gray-700 sm:col-span-2 lg:col-span-1">
            <h3 className="text-sm sm:text-lg font-semibold mb-2 text-gray-300">Admin Access</h3>
            <p className="text-xs sm:text-sm text-gray-400">Full administrative privileges</p>
          </div>
        </div>

        {/* Add/Edit Profile Form */}
        {showAddForm && (
          <div className="bg-gray-800 rounded-lg mb-6 sm:mb-8 shadow-lg border border-gray-700">
            <div className="flex justify-between items-center p-4 sm:p-6 border-b border-gray-700">
              <h2 className="text-xl sm:text-2xl font-semibold text-pink-500">
                {editingService ? 'Edit Profile' : 'Add New Profile'}
              </h2>
              <button
                onClick={() => {
                  setShowAddForm(false);
                  setEditingService(null);
                }}
                className="bg-gray-600 hover:bg-gray-700 text-white p-2 rounded-md transition-colors"
                aria-label="Close form"
              >
                <XIcon className="h-5 w-5" />
              </button>
            </div>
            <div className="p-4 sm:p-6">
              <AdminProfileForm
                initialData={editingService}
                onProfileAdded={handleProfileAdded}
              />
            </div>
          </div>
        )}

        {/* Profiles List */}
        <div className="bg-gray-800 rounded-lg shadow-lg border border-gray-700">
          <div className="p-4 sm:p-6 border-b border-gray-700">
            <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-4">
              <h2 className="text-xl sm:text-2xl font-semibold text-pink-500">Manage Profiles</h2>
              <button
                onClick={() => setShowAddForm(true)}
                className="bg-pink-600 hover:bg-pink-700 text-white px-4 py-2 rounded-md font-medium transition-colors flex items-center justify-center space-x-2 w-full sm:w-auto"
              >
                <PlusIcon className="h-5 w-5" />
                <span>Add New Profile</span>
              </button>
            </div>

            {/* Search */}
            <div>
              <input
                type="text"
                placeholder="Search profiles by name or nationality..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full px-3 sm:px-4 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent text-sm sm:text-base"
              />
            </div>
          </div>

          {/* Desktop Table View - Hidden on Mobile */}
          <div className="hidden lg:block overflow-x-auto">
            {filteredServices.length === 0 ? (
              <div className="text-center py-12">
                <div className="text-6xl mb-4">👤</div>
                <h3 className="text-lg font-medium text-gray-300 mb-2">
                  {searchTerm ? 'No profiles found' : 'No profiles available'}
                </h3>
                <p className="text-gray-500">
                  {searchTerm ? 'Try adjusting your search terms' : 'Start by adding a new profile'}
                </p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Profile
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Details
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredServices.map((service) => (
                    <tr key={service._id} className="hover:bg-gray-700 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="h-12 w-12 rounded-full bg-gray-600 flex items-center justify-center mr-4 shrink-0">
                            {service.image ? (
                              <Image
                                width={48}
                                height={48}
                                src={service.image}
                                alt={service.name}
                                className="h-12 w-12 rounded-full object-cover"
                              />
                            ) : (
                              <span className="text-gray-300 font-medium">
                                {service.name?.[0]?.toUpperCase() || 'P'}
                              </span>
                            )}
                          </div>
                          <div>
                            <div className="text-sm font-medium text-white">
                              {service.name}
                            </div>
                            <div className="text-sm text-gray-400">
                              {service.age} years old
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-300">
                          <div>{service.nationality || 'N/A'}</div>
                          <div className="text-pink-400 font-medium">{service.price}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                          service.availability === 'Available now'
                            ? 'bg-green-100 text-green-800'
                            : 'bg-gray-100 text-gray-800'
                        }`}>
                          {service.availability || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex space-x-2">
                          <button
                            onClick={() => handleEdit(service)}
                            className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
                          >
                            <PencilIcon className="h-4 w-4 mr-1" />
                            Edit
                          </button>
                          <button
                            onClick={() => handleDelete(service._id)}
                            disabled={actionLoading[service._id]}
                            className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-red-700 bg-red-100 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {actionLoading[service._id] ? (
                              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-700 mr-1"></div>
                            ) : (
                              <TrashIcon className="h-4 w-4 mr-1" />
                            )}
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Mobile Card View - Visible only on Mobile & Tablet */}
          <div className="lg:hidden">
            {filteredServices.length === 0 ? (
              <div className="text-center py-12 px-4">
                <div className="text-5xl sm:text-6xl mb-4">👤</div>
                <h3 className="text-base sm:text-lg font-medium text-gray-300 mb-2">
                  {searchTerm ? 'No profiles found' : 'No profiles available'}
                </h3>
                <p className="text-sm sm:text-base text-gray-500">
                  {searchTerm ? 'Try adjusting your search terms' : 'Start by adding a new profile'}
                </p>
              </div>
            ) : (
              <div className="divide-y divide-gray-700">
                {filteredServices.map((service) => (
                  <div key={service._id} className="p-4 sm:p-6 hover:bg-gray-700 transition-colors">
                    {/* Profile Header */}
                    <div className="flex items-start space-x-3 sm:space-x-4 mb-4">
                      <div className="h-14 w-14 sm:h-16 sm:w-16 rounded-full bg-gray-600 flex items-center justify-center shrink-0">
                        {service.image ? (
                          <Image
                            width={64}
                            height={64}
                            src={service.image}
                            alt={service.name}
                            className="h-14 w-14 sm:h-16 sm:w-16 rounded-full object-cover"
                          />
                        ) : (
                          <span className="text-gray-300 font-medium text-lg sm:text-xl">
                            {service.name?.[0]?.toUpperCase() || 'P'}
                          </span>
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="text-base sm:text-lg font-semibold text-white mb-1 truncate">
                          {service.name}
                        </h3>
                        <p className="text-sm text-gray-400 mb-2">
                          {service.age} years old
                        </p>
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                          service.availability === 'Available now'
                            ? 'bg-green-100 text-green-800'
                            : 'bg-gray-100 text-gray-800'
                        }`}>
                          {service.availability || 'Unknown'}
                        </span>
                      </div>
                    </div>

                    {/* Profile Details */}
                    <div className="space-y-2 mb-4 bg-gray-900/50 rounded-lg p-3 sm:p-4">
                      <div className="flex justify-between items-center">
                        <span className="text-xs sm:text-sm text-gray-400">Nationality</span>
                        <span className="text-xs sm:text-sm text-gray-300 font-medium">
                          {service.nationality || 'N/A'}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-xs sm:text-sm text-gray-400">Price</span>
                        <span className="text-sm sm:text-base text-pink-400 font-semibold">
                          {service.price}
                        </span>
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex flex-col sm:flex-row gap-2 sm:gap-3">
                      <button
                        onClick={() => handleEdit(service)}
                        className="flex-1 inline-flex items-center justify-center px-4 py-2.5 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
                      >
                        <PencilIcon className="h-4 w-4 mr-2" />
                        Edit Profile
                      </button>
                      <button
                        onClick={() => handleDelete(service._id)}
                        disabled={actionLoading[service._id]}
                        className="flex-1 inline-flex items-center justify-center px-4 py-2.5 border border-transparent text-sm font-medium rounded-md text-red-700 bg-red-100 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {actionLoading[service._id] ? (
                          <>
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-700 mr-2"></div>
                            Deleting...
                          </>
                        ) : (
                          <>
                            <TrashIcon className="h-4 w-4 mr-2" />
                            Delete
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
