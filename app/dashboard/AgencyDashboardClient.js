'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import AdminProfileForm from '@/components/AdminProfileForm';

export default function AgencyDashboardClient({ initialServices, initialUser }) {
  const [services, setServices] = useState(initialServices || []);
  const [user, setUser] = useState(initialUser || null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [showAddForm, setShowAddForm] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const fetchData = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        router.push('/login');
        return;
      }

      try {
        // Fetch user data
        const userResponse = await fetch('/api/auth/verify', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (userResponse.ok) {
          const userData = await userResponse.json();

          // Verify user is agency
          if (userData.role !== 'agency') {
            router.push('/');
            return;
          }

          setUser(userData);
        } else {
          router.push('/login');
        }
      } catch (error) {
        console.error('Error fetching data:', error);
        router.push('/login');
      }
    };

    fetchData();
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    router.push('/login');
  };

  const refreshServices = async () => {
    const token = localStorage.getItem('token');
    try {
      const response = await fetch('/api/services', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setServices(data.services || []);
      }
    } catch (error) {
      console.error('Error refreshing services:', error);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-gray-900 to-black flex items-center justify-center">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-16 h-16 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin"></div>
          <p className="text-indigo-300 text-lg font-medium">Loading Agency Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-gray-900 to-black">
      {/* Header */}
      <div className="bg-black/30 backdrop-blur-sm border-b border-indigo-500/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 rounded-full bg-gradient-to-r from-indigo-500 to-blue-600 flex items-center justify-center">
                <span className="text-white font-bold text-xl">🏢</span>
              </div>
              <div>
                <h1 className="text-3xl font-bold text-white">Agency Control Panel</h1>
                <p className="text-indigo-300">Professional Team Management</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm text-indigo-300">Welcome, {user?.agencyName || user?.email?.split('@')[0]}</p>
                <p className="text-xs text-gray-400">Agency Manager</p>
              </div>
              <button
                onClick={handleLogout}
                className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 px-6 py-2 rounded-full text-white font-medium transition-all duration-200 shadow-lg hover:shadow-red-500/25"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Tab Navigation */}
        <div className="bg-gradient-to-r from-gray-900/50 to-black/50 backdrop-blur-sm border border-indigo-500/20 rounded-2xl shadow-2xl mb-8">
          <div className="border-b border-indigo-500/20">
            <nav className="flex space-x-0 px-2 py-2">
              {[
                { id: 'overview', label: 'Dashboard Overview', icon: '📊', color: 'from-indigo-600 to-blue-600' },
                { id: 'team', label: 'Team Management', icon: '👥', color: 'from-blue-600 to-indigo-600' },
                { id: 'analytics', label: 'Performance', icon: '📈', color: 'from-green-600 to-blue-600' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 py-4 px-6 rounded-xl font-medium text-sm flex items-center justify-center space-x-2 transition-all duration-200 mx-1 ${
                    activeTab === tab.id
                      ? `bg-gradient-to-r ${tab.color} text-white shadow-lg scale-105`
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <span className="text-lg">{tab.icon}</span>
                  <span>{tab.label}</span>
                </button>
              ))}
            </nav>
          </div>

          {/* Tab Content */}
          <div className="p-8">
            {activeTab === 'overview' && (
              <div>
                <div className="mb-8">
                  <h2 className="text-3xl font-bold text-white mb-2">Agency Overview</h2>
                  <p className="text-indigo-300">Monitor your team's performance and business metrics</p>
                </div>

                {/* Quick Stats */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                  <div className="bg-gradient-to-br from-indigo-800/50 to-blue-900/50 backdrop-blur-sm border border-indigo-500/20 rounded-2xl p-6 shadow-xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-indigo-300 text-sm font-medium">Team Profiles</p>
                        <p className="text-3xl font-bold text-white mt-2">{services.length}</p>
                      </div>
                      <div className="w-12 h-12 bg-indigo-500/20 rounded-full flex items-center justify-center">
                        <span className="text-2xl">💼</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-green-800/50 to-emerald-900/50 backdrop-blur-sm border border-green-500/20 rounded-2xl p-6 shadow-xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-green-300 text-sm font-medium">Active Now</p>
                        <p className="text-3xl font-bold text-white mt-2">
                          {services.filter(s => s.availability === 'Available now').length}
                        </p>
                      </div>
                      <div className="w-12 h-12 bg-green-500/20 rounded-full flex items-center justify-center">
                        <span className="text-2xl">✨</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-purple-800/50 to-pink-900/50 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-6 shadow-xl">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-purple-300 text-sm font-medium">Agency Revenue</p>
                        <p className="text-3xl font-bold text-white mt-2">$12.4k</p>
                      </div>
                      <div className="w-12 h-12 bg-purple-500/20 rounded-full flex items-center justify-center">
                        <span className="text-2xl">💰</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Quick Actions */}
                <div className="bg-gradient-to-r from-indigo-800/30 to-blue-800/30 backdrop-blur-sm border border-indigo-500/20 rounded-2xl p-6 mb-8 shadow-xl">
                  <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
                    <span className="mr-2">🚀</span>
                    Quick Actions
                  </h2>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <button
                      onClick={() => {
                        setActiveTab('team');
                        setShowAddForm(true);
                      }}
                      className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white px-6 py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-indigo-500/25 flex items-center justify-center space-x-2"
                    >
                      <span className="text-xl">➕</span>
                      <span>Add Team Member</span>
                    </button>
                    <button
                      onClick={() => setActiveTab('analytics')}
                      className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-6 py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-green-500/25 flex items-center justify-center space-x-2"
                    >
                      <span className="text-xl">📈</span>
                      <span>Performance</span>
                    </button>
                    <button className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-6 py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-purple-500/25 flex items-center justify-center space-x-2">
                      <span className="text-xl">💬</span>
                      <span>Messages</span>
                    </button>
                    <button className="bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white px-6 py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-orange-500/25 flex items-center justify-center space-x-2">
                      <span className="text-xl">⚙️</span>
                      <span>Settings</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'team' && (
              <div>
                <div className="mb-8">
                  <h2 className="text-3xl font-bold text-white mb-2">Team Management</h2>
                  <p className="text-blue-300">Manage your escort team profiles and performance</p>
                </div>

                {/* Add Profile Form */}
                {showAddForm && (
                  <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-gradient-to-br from-gray-900 to-black border border-indigo-500/20 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
                      <div className="sticky top-0 bg-gradient-to-r from-indigo-900/80 to-blue-900/80 backdrop-blur-sm border-b border-indigo-500/20 p-6">
                        <div className="flex justify-between items-center">
                          <h2 className="text-2xl font-bold text-white flex items-center">
                            <span className="mr-3">✨</span>
                            Add New Team Member
                          </h2>
                          <button
                            onClick={() => setShowAddForm(false)}
                            className="w-10 h-10 bg-red-500/20 hover:bg-red-500/30 rounded-full flex items-center justify-center text-red-400 hover:text-red-300 transition-all duration-200"
                          >
                            ✕
                          </button>
                        </div>
                      </div>
                      <div className="p-6">
                        <AdminProfileForm
                          onProfileAdded={() => {
                            setShowAddForm(false);
                            refreshServices();
                          }}
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Team Profiles Section */}
                <div className="bg-gradient-to-br from-blue-800/20 to-indigo-800/20 backdrop-blur-sm border border-indigo-500/20 rounded-2xl shadow-xl">
                  <div className="p-6 border-b border-indigo-500/20">
                    <div className="flex justify-between items-center">
                      <h2 className="text-2xl font-bold text-white flex items-center">
                        <span className="mr-3">👥</span>
                        Team Members
                      </h2>
                      <div className="flex items-center space-x-4">
                        <div className="text-sm text-indigo-300">
                          {services.length} {services.length === 1 ? 'member' : 'members'} total
                        </div>
                        <button
                          onClick={() => setShowAddForm(true)}
                          className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 shadow-lg hover:shadow-indigo-500/25 flex items-center space-x-2"
                        >
                          <span>✨</span>
                          <span>Add Member</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="p-6">
                    {services.length === 0 ? (
                      <div className="text-center py-16">
                        <div className="w-24 h-24 bg-gradient-to-br from-indigo-500/20 to-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                          <span className="text-4xl">🎆</span>
                        </div>
                        <h3 className="text-2xl font-bold text-white mb-4">
                          Build Your Team
                        </h3>
                        <p className="text-indigo-300 mb-8 max-w-md mx-auto">
                          Start building your professional team by adding escort profiles to represent your agency.
                        </p>
                        <button
                          onClick={() => setShowAddForm(true)}
                          className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white px-8 py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-indigo-500/25 inline-flex items-center space-x-2"
                        >
                          <span className="text-xl">✨</span>
                          <span>Add First Team Member</span>
                        </button>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {services.map((service) => (
                          <div key={service._id} className="bg-gradient-to-br from-indigo-800/20 to-blue-800/20 backdrop-blur-sm border border-indigo-500/20 rounded-xl p-6 shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1">
                            <div className="flex items-start justify-between mb-4">
                              <div className="flex items-center space-x-3">
                                <div className="w-12 h-12 bg-gradient-to-r from-indigo-500 to-blue-500 rounded-full flex items-center justify-center">
                                  <span className="text-white font-bold">{service.name?.[0]?.toUpperCase()}</span>
                                </div>
                                <div>
                                  <h3 className="text-lg font-bold text-white">{service.name}</h3>
                                  <p className="text-indigo-300 text-sm">{service.nationality || 'Not specified'}</p>
                                </div>
                              </div>
                              <div className="flex items-center space-x-1">
                                <span className={`w-3 h-3 rounded-full ${
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

                            <div className="space-y-3 mb-6">
                              <div className="flex justify-between items-center">
                                <span className="text-indigo-300 text-sm">Starting Rate</span>
                                <span className="text-white font-bold">{service.price}</span>
                              </div>
                              <div className="flex justify-between items-center">
                                <span className="text-indigo-300 text-sm">Profile Views</span>
                                <span className="text-white font-bold">234</span>
                              </div>
                              <div className="flex justify-between items-center">
                                <span className="text-indigo-300 text-sm">Bookings</span>
                                <span className="text-green-400 font-bold">18 ✅</span>
                              </div>
                            </div>

                            <div className="flex space-x-3">
                              <button className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 text-sm">
                                ✏️ Edit
                              </button>
                              <button className="flex-1 bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 text-sm">
                                👁️ View
                              </button>
                              <button className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200 text-sm">
                                🗑️
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'analytics' && (
              <div>
                <div className="mb-8">
                  <h2 className="text-3xl font-bold text-white mb-2">Performance Analytics</h2>
                  <p className="text-green-300">Track your agency's performance and team metrics</p>
                </div>

                <div className="bg-gradient-to-br from-green-800/20 to-emerald-800/20 backdrop-blur-sm border border-green-500/20 rounded-2xl p-8 shadow-xl">
                  <div className="text-center py-16">
                    <div className="w-24 h-24 bg-gradient-to-br from-green-500/20 to-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                      <span className="text-4xl">📈</span>
                    </div>
                    <h3 className="text-2xl font-bold text-white mb-4">
                      Advanced Analytics Coming Soon
                    </h3>
                    <p className="text-green-300 max-w-md mx-auto">
                      Comprehensive analytics including team performance, revenue tracking, client engagement, and booking trends will be available here.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
