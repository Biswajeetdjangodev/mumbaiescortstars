'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import dynamic from 'next/dynamic';

// Create a wrapper component for CKEditor
const EditorWrapper = dynamic(() => {
  return import('@ckeditor/ckeditor5-react').then((mod) => {
    const { CKEditor } = mod;
    return import('@ckeditor/ckeditor5-build-classic').then((editorMod) => {
      const ClassicEditor = editorMod.default;

      return function EditorComponent({ data, onChange, config }) {
        return (
          <CKEditor
            editor={ClassicEditor}
            data={data}
            onChange={onChange}
            config={config}
          />
        );
      };
    });
  });
}, {
  ssr: false,
  loading: () => (
    <div className="p-4 text-center text-gray-500">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-2"></div>
      Loading editor...
    </div>
  )
});

const ProfileManagement = dynamic(() => import('@/components/ProfileManagement'), {
  loading: () => (
    <div className="min-h-[400px] flex items-center justify-center">
      <div className="flex flex-col items-center space-y-4">
        <div className="w-12 h-12 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
        <p className="text-blue-300">Loading Profile Management...</p>
      </div>
    </div>
  ),
  ssr: false
});

export default function AdminDashboard() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('users');
  const [seoSection, setSeoSection] = useState('homepage-top');
  const [seoContent, setSeoContent] = useState('');
  const [seoTitle, setSeoTitle] = useState('');
  const [seoDescription, setSeoDescription] = useState('');
  const [layoutTitle, setLayoutTitle] = useState('');
  const [layoutDescription, setLayoutDescription] = useState('');
  const [h1, setH1] = useState('');
  const [schema, setSchema] = useState('');
  const [metaKeywords, setMetaKeywords] = useState('');
  const [canonicalUrl, setCanonicalUrl] = useState('');
  const [robots, setRobots] = useState('index, follow');
  const [ogTitle, setOgTitle] = useState('');
  const [ogDescription, setOgDescription] = useState('');
  const [ogImage, setOgImage] = useState('');
  const [twitterTitle, setTwitterTitle] = useState('');
  const [twitterDescription, setTwitterDescription] = useState('');
  const [twitterImage, setTwitterImage] = useState('');
  const [isClient, setIsClient] = useState(false);
  const [actionLoading, setActionLoading] = useState({});
  const [seoLoading, setSeoLoading] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const router = useRouter();

  // Handle client-side rendering
  useEffect(() => {
    setIsClient(true);
  }, []);

  const fetchUsers = useCallback(async () => {
    if (!isClient) return;

    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }

    try {
      const response = await fetch('/api/auth/users', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setUsers(data);
      } else {
        console.error('Failed to fetch users:', response.status);
        if (response.status === 401) {
          router.push('/login');
        }
      }
    } catch (error) {
      console.error('Error fetching users:', error);
    } finally {
      setLoading(false);
    }
  }, [isClient, router]);

  useEffect(() => {
    if (isClient) {
      fetchUsers();
    }
  }, [isClient, fetchUsers]);

  const handleBlockUser = async (userId) => {
    if (!isClient) return;
    
    setActionLoading(prev => ({ ...prev, [userId]: true }));
    const token = localStorage.getItem('token');
    
    try {
      const response = await fetch('/api/auth/manageUser', {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId, action: 'block' }),
      });

      if (response.ok) {
        await fetchUsers();
      } else {
        console.error('Failed to block user');
      }
    } catch (error) {
      console.error('Error blocking user:', error);
    } finally {
      setActionLoading(prev => ({ ...prev, [userId]: false }));
    }
  };

  const handleUnblockUser = async (userId) => {
    if (!isClient) return;
    
    setActionLoading(prev => ({ ...prev, [userId]: true }));
    const token = localStorage.getItem('token');
    
    try {
      const response = await fetch('/api/auth/manageUser', {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId, action: 'unblock' }),
      });

      if (response.ok) {
        await fetchUsers();
      } else {
        console.error('Failed to unblock user');
      }
    } catch (error) {
      console.error('Error unblocking user:', error);
    } finally {
      setActionLoading(prev => ({ ...prev, [userId]: false }));
    }
  };

  const handleSeoSubmit = async () => {
    if (!isClient) return;

    setSeoLoading(true);
    const token = localStorage.getItem('token');

    try {
      let apiEndpoint = '';
      let requestBody = {};

      // Route to appropriate API endpoint based on section
      switch (seoSection) {
        case 'homepage-top':
          apiEndpoint = '/api/homepage-top';
          requestBody = { h1, seodescription: seoDescription };
          break;
        case 'homepage-bottom':
          apiEndpoint = '/api/homepage-bottom';
          requestBody = { content: seoContent };
          break;
        case 'layout':
          apiEndpoint = '/api/layout';
          requestBody = { title: layoutTitle, description: layoutDescription };
          break;
        case 'facebook':
          apiEndpoint = '/api/facebook';
          requestBody = { ogTitle, ogDescription, ogImage };
          break;
        case 'twitter':
          apiEndpoint = '/api/twitter';
          requestBody = { twitterTitle, twitterDescription, twitterImage };
          break;
        case 'meta':
          apiEndpoint = '/api/meta';
          requestBody = {
            seotitle: seoTitle,
            seodescription: seoDescription,
            metaKeywords: metaKeywords.split(',').map(k => k.trim()).filter(k => k),
            canonicalUrl,
            robots
          };
          break;
        default:
          alert('Unknown section selected');
          return;
      }

      const response = await fetch(apiEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      if (response.ok) {
        const sectionName = seoSection === 'layout' ? 'Layout settings' :
                           seoSection === 'homepage-top' ? 'Homepage Header' :
                           seoSection === 'homepage-bottom' ? 'Homepage Footer' :
                           seoSection === 'facebook' ? 'Facebook Settings' :
                           seoSection === 'twitter' ? 'Twitter Settings' :
                           seoSection === 'meta' ? 'Meta Tags' :
                           `${seoSection.charAt(0).toUpperCase() + seoSection.slice(1).replace('-', ' ')}`;
        alert(`${sectionName} saved successfully!`);
      } else {
        const errorData = await response.json();
        alert(`Failed to save: ${errorData.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Error saving content:', error);
      alert('Error saving content');
    } finally {
      setSeoLoading(false);
    }
  };

  if (!isClient || loading) {
    return (
      <div className="min-h-screen bg-linear-to-br from-blue-900 via-gray-900 to-black flex items-center justify-center px-4">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-12 h-12 sm:w-16 sm:h-16 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
          <p className="text-blue-300 text-base sm:text-lg font-medium text-center">Loading Admin Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      {/* <div className="bg-black/30 backdrop-blur-sm border-b border-blue-500/20 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4 sm:py-6">
            <div className="flex items-center space-x-2 sm:space-x-4">
              <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-full bg-gradient-to-r from-blue-500 to-cyan-500 flex items-center justify-center flex-shrink-0">
                <span className="text-white font-bold text-lg sm:text-xl">🛡️</span>
              </div>
              <div className="min-w-0">
                <h1 className="text-lg sm:text-2xl lg:text-3xl font-bold text-white truncate">Admin Control Panel</h1>
                <p className="text-blue-300 text-xs sm:text-sm hidden sm:block">System Administration Dashboard</p>
              </div>
            </div>
            <div className="flex items-center space-x-2 sm:space-x-4">
              <div className="text-right hidden md:block">
                <p className="text-sm text-blue-300">Administrator</p>
                <p className="text-xs text-gray-400">Full System Access</p>
              </div>
              <button 
                onClick={() => {
                  if (isClient) {
                    localStorage.removeItem('token');
                    router.push('/login');
                  }
                }}
                className="bg-linear-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 px-3 py-2 sm:px-6 sm:py-2 rounded-full text-white font-medium transition-all duration-200 shadow-lg hover:shadow-red-500/25 text-sm sm:text-base whitespace-nowrap"
              >
                <span className="hidden sm:inline">Sign Out</span>
                <span className="sm:hidden">🚪</span>
              </button>
            </div>
          </div>
        </div>
      </div> */}

      <div className="max-w-7xl mx-auto px-0 sm:px-6 lg:px-8 py-4 sm:py-8 bg-[#191919]">
        {/* Tab Navigation */}
        <div className="bg-linear-to-br from-blue-900 via-gray-900 to-black backdrop-blur-sm border border-blue-500/20 rounded-none sm:rounded-2xl shadow-2xl mb-4 sm:mb-8">
          <div className="border-b border-blue-500/20">
            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="md:hidden w-full px-4 py-3 flex items-center justify-between text-white"
            >
              <span className="font-medium">
                {activeTab === 'users' && '👥 User Management'}
                {activeTab === 'seo' && '🔍 SEO Management'}
                {activeTab === 'profiles' && '👤 Profile Management'}
              </span>
              <span className="text-xl">{isMobileMenuOpen ? '▲' : '▼'}</span>
            </button>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex space-x-0 px-2 py-2">
              {[
                { id: 'users', label: 'User Management', icon: '👥', color: 'from-purple-600 to-blue-600' },
                { id: 'seo', label: 'SEO Management', icon: '🔍', color: 'from-green-600 to-teal-600' },
                { id: 'profiles', label: 'Profile Management', icon: '👤', color: 'from-pink-600 to-purple-600' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 py-3 lg:py-4 px-3 lg:px-6 rounded-xl font-medium text-sm flex items-center justify-center space-x-2 transition-all duration-200 mx-1 ${
                    activeTab === tab.id
                      ? `bg-linear-to-r ${tab.color} text-white shadow-lg scale-105`
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <span className="text-lg">{tab.icon}</span>
                  <span className="hidden lg:inline">{tab.label}</span>
                  <span className="lg:hidden">{tab.label.split(' ')[0]}</span>
                </button>
              ))}
            </nav>

            {/* Mobile Navigation */}
            {isMobileMenuOpen && (
              <nav className="md:hidden border-t border-blue-500/20">
                {[
                  { id: 'users', label: 'User Management', icon: '👥', color: 'from-purple-600 to-blue-600' },
                  { id: 'seo', label: 'SEO Management', icon: '🔍', color: 'from-green-600 to-teal-600' },
                  { id: 'profiles', label: 'Profile Management', icon: '👤', color: 'from-pink-600 to-purple-600' }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setActiveTab(tab.id);
                      setIsMobileMenuOpen(false);
                    }}
                    className={`w-full py-3 px-4 font-medium text-sm flex items-center space-x-3 transition-all duration-200 border-b border-blue-500/10 last:border-b-0 ${
                      activeTab === tab.id
                        ? `bg-linear-to-r ${tab.color} text-white`
                        : 'text-gray-400 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    <span className="text-lg">{tab.icon}</span>
                    <span>{tab.label}</span>
                  </button>
                ))}
              </nav>
            )}
          </div>

          {/* Tab Content */}
          <div className="p-4 sm:p-6 lg:p-8">
            {activeTab === 'users' && (
              <div>
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-6 sm:mb-8 gap-4">
                  <div>
                    <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">User Management</h2>
                    <p className="text-blue-300 text-sm sm:text-base">Monitor and manage all registered users</p>
                  </div>
                  <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 backdrop-blur-sm border border-blue-500/20 rounded-xl sm:rounded-2xl px-4 sm:px-6 py-3 w-fit">
                    <span className="text-blue-300 text-xs sm:text-sm font-medium">Total Users: </span>
                    <span className="text-white text-xl sm:text-2xl font-bold">{users.length}</span>
                  </div>
                </div>

                {users.length === 0 ? (
                  <div className="text-center py-12 sm:py-16">
                    <div className="w-20 h-20 sm:w-24 sm:h-24 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                      <span className="text-3xl sm:text-4xl">👥</span>
                    </div>
                    <h3 className="text-xl sm:text-2xl font-bold text-white mb-4">No Users Yet</h3>
                    <p className="text-blue-300 text-sm sm:text-base">The system is ready for user registrations.</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
                    {users.map(user => (
                      <div key={user._id} className="bg-gradient-to-br from-blue-800/20 to-purple-800/20 backdrop-blur-sm border border-blue-500/20 rounded-xl p-4 sm:p-6 shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1">
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex items-center space-x-2 sm:space-x-3 min-w-0">
                            <div className="w-10 h-10 sm:w-12 sm:h-12 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center flex-shrink-0">
                              <span className="text-white font-bold text-sm sm:text-base">{user.email?.[0]?.toUpperCase() || 'U'}</span>
                            </div>
                            <div className="min-w-0">
                              <h3 className="text-base sm:text-lg font-bold text-white truncate">{user.email}</h3>
                              <p className="text-blue-300 text-xs sm:text-sm capitalize">{user.role || 'visitor'}</p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-1 flex-shrink-0">
                            <span className={`w-2 h-2 sm:w-3 sm:h-3 rounded-full ${
                              user.isBlocked ? 'bg-red-500' : 'bg-green-500 animate-pulse'
                            }`}></span>
                            <span className={`text-xs font-medium hidden sm:inline ${
                              user.isBlocked ? 'text-red-400' : 'text-green-400'
                            }`}>
                              {user.isBlocked ? 'Blocked' : 'Active'}
                            </span>
                          </div>
                        </div>
                        
                        <div className="space-y-2 sm:space-y-3 mb-4 sm:mb-6">
                          <div className="flex justify-between items-center">
                            <span className="text-blue-300 text-xs sm:text-sm">Account Type</span>
                            <span className="text-white font-bold capitalize text-xs sm:text-sm">{user.role || 'Visitor'}</span>
                          </div>
                          {user.agencyName && (
                            <div className="flex justify-between items-center">
                              <span className="text-blue-300 text-xs sm:text-sm">Agency Name</span>
                              <span className="text-white font-bold truncate max-w-[120px] text-xs sm:text-sm">{user.agencyName}</span>
                            </div>
                          )}
                          <div className="flex justify-between items-center">
                            <span className="text-blue-300 text-xs sm:text-sm">Status</span>
                            <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                              user.isBlocked 
                                ? 'bg-red-500/20 text-red-400' 
                                : 'bg-green-500/20 text-green-400'
                            }`}>
                              {user.isBlocked ? '🚫 Blocked' : '✅ Active'}
                            </span>
                          </div>
                        </div>
                        
                        <button
                          onClick={() => user.isBlocked ? handleUnblockUser(user._id) : handleBlockUser(user._id)}
                          disabled={actionLoading[user._id]}
                          className={`w-full py-2.5 sm:py-3 px-4 rounded-lg font-medium transition-all duration-200 flex items-center justify-center space-x-2 text-sm sm:text-base ${
                            user.isBlocked
                              ? 'bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white'
                              : 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white'
                          } ${actionLoading[user._id] ? 'opacity-50 cursor-not-allowed' : ''}`}
                        >
                          {actionLoading[user._id] ? (
                            <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                          ) : (
                            <>
                              <span>{user.isBlocked ? '✅' : '🚫'}</span>
                              <span>{user.isBlocked ? 'Unblock User' : 'Block User'}</span>
                            </>
                          )}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'seo' && (
              <div>
                <div className="mb-6 sm:mb-8">
                  <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">SEO Management</h2>
                  <p className="text-green-300 text-sm sm:text-base">Optimize your website for search engines</p>
                </div>

                {/* SEO Section Selector */}
                <div className="mb-6 sm:mb-8">
                  <label className="block text-sm font-medium text-green-300 mb-3 flex items-center">
                    <span className="mr-2">📍</span>
                    Select Content Section
                  </label>
                  <select
                    value={seoSection}
                    onChange={(e) => setSeoSection(e.target.value)}
                    className="w-full max-w-md px-4 py-3 bg-black/20 border border-green-500/20 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                  >
                    <option className="bg-black" value="homepage-top">🏠 Homepage Top</option>
                    <option className="bg-black" value="homepage-bottom">🏠 Homepage Bottom</option>
                    <option className="bg-black" value="layout">📄 Layout (Title & Description)</option>
                    <option className="bg-black" value="facebook">� Facebook (Open Graph)</option>
                    <option className="bg-black" value="twitter">� Twitter Cards</option>
                    <option className="bg-black" value="meta">🔍 Meta Tags</option>
                  </select>
                </div>

                <div className="bg-gradient-to-br from-green-800/20 to-teal-800/20 backdrop-blur-sm border border-green-500/20 rounded-xl sm:rounded-2xl p-4 sm:p-6 lg:p-8 shadow-xl">
                  {seoSection === 'layout' ? (
                    <div className="space-y-6 sm:space-y-8">
                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">📄</span>
                          Layout Title (app/layout.js)
                        </label>
                        <input
                          type="text"
                          placeholder="Enter site title"
                          value={layoutTitle}
                          onChange={(e) => setLayoutTitle(e.target.value)}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                        />
                        <p className="text-xs text-gray-400 mt-1">This will update the title in your layout.js metadata</p>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">📝</span>
                          Layout Description (app/layout.js)
                        </label>
                        <textarea
                          placeholder="Enter site description"
                          value={layoutDescription}
                          onChange={(e) => setLayoutDescription(e.target.value)}
                          rows={4}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                        />
                        <p className="text-xs text-gray-400 mt-1">This will update the description in your layout.js metadata</p>
                      </div>

                      <div className="flex justify-end">
                        <button
                          onClick={handleSeoSubmit}
                          disabled={seoLoading}
                          className={`inline-flex items-center px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 text-white font-medium rounded-xl shadow-lg hover:shadow-green-500/25 transition-all duration-200 space-x-2 text-sm sm:text-base ${
                            seoLoading ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {seoLoading ? (
                            <>
                              <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Saving...</span>
                            </>
                          ) : (
                            <>
                              <span className="text-base sm:text-lg">💾</span>
                              <span>Save Layout Settings</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  ) : seoSection === 'homepage-top' ? (
                    <div className="space-y-6 sm:space-y-8">
                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">🏷️</span>
                          Homepage Header H1
                        </label>
                        <input
                          type="text"
                          placeholder="Enter homepage header H1"
                          value={h1}
                          onChange={(e) => setH1(e.target.value)}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                        />
                        <p className="text-xs text-gray-400 mt-1">This appears in the purple header section at the top of the homepage</p>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">📝</span>
                          Homepage Header Description
                        </label>
                        <textarea
                          placeholder="Enter homepage header description"
                          value={seoDescription}
                          onChange={(e) => setSeoDescription(e.target.value)}
                          rows={4}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                        />
                        <p className="text-xs text-gray-400 mt-1">This appears below the H1 in the purple header section</p>
                      </div>

                      <div className="flex justify-end">
                        <button
                          onClick={handleSeoSubmit}
                          disabled={seoLoading}
                          className={`inline-flex items-center px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 text-white font-medium rounded-xl shadow-lg hover:shadow-green-500/25 transition-all duration-200 space-x-2 text-sm sm:text-base ${
                            seoLoading ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {seoLoading ? (
                            <>
                              <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Saving...</span>
                            </>
                          ) : (
                            <>
                              <span className="text-base sm:text-lg">💾</span>
                              <span>Save Homepage Header</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  ) : seoSection === 'homepage-bottom' ? (
                    <div className="space-y-6 sm:space-y-8">
                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">✏️</span>
                          Homepage Footer Content
                        </label>
                        <div className="bg-black/20 border border-green-500/20 rounded-xl overflow-hidden">
                          <style jsx global>{`
                            .ck-editor__editable {
                              color: white !important;
                              background: rgba(0, 0, 0, 0.2) !important;
                            }
                            .ck-editor__editable p, .ck-editor__editable h1, .ck-editor__editable h2,
                            .ck-editor__editable h3, .ck-editor__editable h4, .ck-editor__editable h5,
                            .ck-editor__editable h6, .ck-editor__editable li, .ck-editor__editable span {
                              color: white !important;
                            }
                            .ck-editor__editable a {
                              color: #60a5fa !important;
                            }
                            .ck-editor__editable blockquote {
                              border-left: 4px solid #22c55e;
                              background: rgba(34, 197, 94, 0.1);
                            }
                            .ck-content {
                              color: white !important;
                            }
                            .ck-content * {
                              color: white !important;
                            }
                          `}</style>
                          <EditorWrapper
                            data={seoContent}
                            onChange={(event, editor) => setSeoContent(editor.getData())}
                            config={{
                              toolbar: [
                                'heading', '|',
                                'bold', 'italic', 'link', '|',
                                'bulletedList', 'numberedList', '|',
                                'outdent', 'indent', '|',
                                'blockQuote', 'insertTable', '|',
                                'undo', 'redo'
                              ],
                              contentsCss: `
                                body {
                                  color: white !important;
                                  background: rgba(0, 0, 0, 0.2) !important;
                                }
                                p, h1, h2, h3, h4, h5, h6, li, span {
                                  color: white !important;
                                }
                                a {
                                  color: #60a5fa !important;
                                }
                                blockquote {
                                  border-left: 4px solid #22c55e;
                                  background: rgba(34, 197, 94, 0.1);
                                }
                              `
                            }}
                          />
                        </div>
                        <p className="text-xs text-gray-400 mt-1">This appears in the purple footer section at the bottom of the homepage</p>
                      </div>

                      <div className="flex justify-end">
                        <button
                          onClick={handleSeoSubmit}
                          disabled={seoLoading}
                          className={`inline-flex items-center px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 text-white font-medium rounded-xl shadow-lg hover:shadow-green-500/25 transition-all duration-200 space-x-2 text-sm sm:text-base ${
                            seoLoading ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {seoLoading ? (
                            <>
                              <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Saving...</span>
                            </>
                          ) : (
                            <>
                              <span className="text-base sm:text-lg">💾</span>
                              <span>Save Homepage Footer</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  ) : seoSection === 'facebook' ? (
                    <div className="space-y-6 sm:space-y-8">
                      <div className="mb-4">
                        <h3 className="text-base sm:text-lg font-semibold text-green-300 mb-4 sm:mb-6 flex items-center">
                          <span className="mr-2">📘</span>
                          Facebook Open Graph Settings
                        </h3>
                        <p className="text-xs text-gray-400 mb-6">Configure how your content appears when shared on Facebook</p>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Facebook Title</label>
                          <input
                            type="text"
                            placeholder="Title for Facebook sharing"
                            value={ogTitle}
                            onChange={(e) => setOgTitle(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Facebook Image URL</label>
                          <input
                            type="url"
                            placeholder="https://example.com/facebook-image.jpg"
                            value={ogImage}
                            onChange={(e) => setOgImage(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Facebook Description</label>
                        <textarea
                          placeholder="Description for Facebook sharing"
                          value={ogDescription}
                          onChange={(e) => setOgDescription(e.target.value)}
                          rows={4}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                        />
                      </div>

                      <div className="flex justify-end">
                        <button
                          onClick={handleSeoSubmit}
                          disabled={seoLoading}
                          className={`inline-flex items-center px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-medium rounded-xl shadow-lg hover:shadow-blue-500/25 transition-all duration-200 space-x-2 text-sm sm:text-base ${
                            seoLoading ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {seoLoading ? (
                            <>
                              <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Saving...</span>
                            </>
                          ) : (
                            <>
                              <span className="text-base sm:text-lg">📘</span>
                              <span>Save Facebook Settings</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  ) : seoSection === 'twitter' ? (
                    <div className="space-y-6 sm:space-y-8">
                      <div className="mb-4">
                        <h3 className="text-base sm:text-lg font-semibold text-green-300 mb-4 sm:mb-6 flex items-center">
                          <span className="mr-2">🐦</span>
                          Twitter Card Settings
                        </h3>
                        <p className="text-xs text-gray-400 mb-6">Configure how your content appears when shared on Twitter</p>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Twitter Title</label>
                          <input
                            type="text"
                            placeholder="Title for Twitter sharing"
                            value={twitterTitle}
                            onChange={(e) => setTwitterTitle(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Twitter Image URL</label>
                          <input
                            type="url"
                            placeholder="https://example.com/twitter-image.jpg"
                            value={twitterImage}
                            onChange={(e) => setTwitterImage(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Twitter Description</label>
                        <textarea
                          placeholder="Description for Twitter sharing"
                          value={twitterDescription}
                          onChange={(e) => setTwitterDescription(e.target.value)}
                          rows={4}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                        />
                      </div>

                      <div className="flex justify-end">
                        <button
                          onClick={handleSeoSubmit}
                          disabled={seoLoading}
                          className={`inline-flex items-center px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-blue-400 to-blue-500 hover:from-blue-500 hover:to-blue-600 text-white font-medium rounded-xl shadow-lg hover:shadow-blue-500/25 transition-all duration-200 space-x-2 text-sm sm:text-base ${
                            seoLoading ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {seoLoading ? (
                            <>
                              <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Saving...</span>
                            </>
                          ) : (
                            <>
                              <span className="text-base sm:text-lg">🐦</span>
                              <span>Save Twitter Settings</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  ) : seoSection === 'meta' ? (
                    <div className="space-y-6 sm:space-y-8">
                      <div className="mb-4">
                        <h3 className="text-base sm:text-lg font-semibold text-green-300 mb-4 sm:mb-6 flex items-center">
                          <span className="mr-2">🔍</span>
                          Meta Tags Settings
                        </h3>
                        <p className="text-xs text-gray-400 mb-6">Configure general meta tags for search engines</p>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🏷️</span>
                            SEO Title
                          </label>
                          <input
                            type="text"
                            placeholder="Page title for search engines"
                            value={seoTitle}
                            onChange={(e) => setSeoTitle(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🔗</span>
                            Canonical URL
                          </label>
                          <input
                            type="url"
                            placeholder="https://example.com/canonical"
                            value={canonicalUrl}
                            onChange={(e) => setCanonicalUrl(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">📝</span>
                          SEO Description
                        </label>
                        <textarea
                          placeholder="Meta description for search engines"
                          value={seoDescription}
                          onChange={(e) => setSeoDescription(e.target.value)}
                          rows={4}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                        />
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🔑</span>
                            Meta Keywords
                          </label>
                          <input
                            type="text"
                            placeholder="keyword1, keyword2, keyword3"
                            value={metaKeywords}
                            onChange={(e) => setMetaKeywords(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🤖</span>
                            Robots Meta
                          </label>
                          <select
                            value={robots}
                            onChange={(e) => setRobots(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          >
                            <option className="bg-black" value="index, follow">index, follow</option>
                            <option className="bg-black" value="noindex, follow">noindex, follow</option>
                            <option className="bg-black" value="index, nofollow">index, nofollow</option>
                            <option className="bg-black" value="noindex, nofollow">noindex, nofollow</option>
                          </select>
                        </div>
                      </div>

                      <div className="flex justify-end">
                        <button
                          onClick={handleSeoSubmit}
                          disabled={seoLoading}
                          className={`inline-flex items-center px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white font-medium rounded-xl shadow-lg hover:shadow-gray-500/25 transition-all duration-200 space-x-2 text-sm sm:text-base ${
                            seoLoading ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {seoLoading ? (
                            <>
                              <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Saving...</span>
                            </>
                          ) : (
                            <>
                              <span className="text-base sm:text-lg">🔍</span>
                              <span>Save Meta Settings</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-6 sm:space-y-8">
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🏷️</span>
                            SEO Title
                          </label>
                          <input
                            type="text"
                            placeholder="Enter SEO title"
                            value={seoTitle}
                            onChange={(e) => setSeoTitle(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🏷️</span>
                            H1 Tag
                          </label>
                          <input
                            type="text"
                            placeholder="Enter H1 tag"
                            value={h1}
                            onChange={(e) => setH1(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">📝</span>
                          SEO Description
                        </label>
                        <textarea
                          placeholder="Enter SEO description"
                          value={seoDescription}
                          onChange={(e) => setSeoDescription(e.target.value)}
                          rows={4}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                        />
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🔑</span>
                            Meta Keywords
                          </label>
                          <input
                            type="text"
                            placeholder="keyword1, keyword2, keyword3"
                            value={metaKeywords}
                            onChange={(e) => setMetaKeywords(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                            <span className="mr-2">🔗</span>
                            Canonical URL
                          </label>
                          <input
                            type="url"
                            placeholder="https://example.com/"
                            value={canonicalUrl}
                            onChange={(e) => setCanonicalUrl(e.target.value)}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">🤖</span>
                          Robots Meta
                        </label>
                        <select
                          value={robots}
                          onChange={(e) => setRobots(e.target.value)}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                        >
                          <option className="bg-black" value="index, follow">index, follow</option>
                          <option className="bg-black" value="noindex, follow">noindex, follow</option>
                          <option className="bg-black" value="index, nofollow">index, nofollow</option>
                          <option className="bg-black" value="noindex, nofollow">noindex, nofollow</option>
                        </select>
                      </div>

                      <div className="border-t border-green-500/20 pt-6 sm:pt-8">
                        <h3 className="text-base sm:text-lg font-semibold text-green-300 mb-4 sm:mb-6 flex items-center">
                          <span className="mr-2">📘</span>
                          Open Graph (Facebook)
                        </h3>
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6 mb-4 sm:mb-6">
                          <div>
                            <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">OG Title</label>
                            <input
                              type="text"
                              placeholder="Open Graph title"
                              value={ogTitle}
                              onChange={(e) => setOgTitle(e.target.value)}
                              className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                            />
                          </div>
                          <div>
                            <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">OG Image URL</label>
                            <input
                              type="url"
                              placeholder="https://example.com/image.jpg"
                              value={ogImage}
                              onChange={(e) => setOgImage(e.target.value)}
                              className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                            />
                          </div>
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">OG Description</label>
                          <textarea
                            placeholder="Open Graph description"
                            value={ogDescription}
                            onChange={(e) => setOgDescription(e.target.value)}
                            rows={3}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                          />
                        </div>
                      </div>

                      <div className="border-t border-green-500/20 pt-6 sm:pt-8">
                        <h3 className="text-base sm:text-lg font-semibold text-green-300 mb-4 sm:mb-6 flex items-center">
                          <span className="mr-2">🐦</span>
                          Twitter Cards
                        </h3>
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6 mb-4 sm:mb-6">
                          <div>
                            <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Twitter Title</label>
                            <input
                              type="text"
                              placeholder="Twitter card title"
                              value={twitterTitle}
                              onChange={(e) => setTwitterTitle(e.target.value)}
                              className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                            />
                          </div>
                          <div>
                            <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Twitter Image URL</label>
                            <input
                              type="url"
                              placeholder="https://example.com/image.jpg"
                              value={twitterImage}
                              onChange={(e) => setTwitterImage(e.target.value)}
                              className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 text-sm sm:text-base"
                            />
                          </div>
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3">Twitter Description</label>
                          <textarea
                            placeholder="Twitter card description"
                            value={twitterDescription}
                            onChange={(e) => setTwitterDescription(e.target.value)}
                            rows={3}
                            className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none text-sm sm:text-base"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 items-center">
                          <span className="mr-2">✏️</span>
                          Content
                        </label>
                        <div className="bg-black/20 border border-green-500/20 rounded-xl overflow-hidden">
                          <EditorWrapper
                            data={seoContent}
                            onChange={(event, editor) => setSeoContent(editor.getData())}
                            config={{
                              toolbar: [
                                'heading', '|',
                                'bold', 'italic', 'link', '|',
                                'bulletedList', 'numberedList', '|',
                                'outdent', 'indent', '|',
                                'blockQuote', 'insertTable', '|',
                                'undo', 'redo'
                              ]
                            }}
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs sm:text-sm font-medium text-green-300 mb-2 sm:mb-3 flex items-center">
                          <span className="mr-2">📦</span>
                          Schema (JSON-LD)
                        </label>
                        <textarea
                          placeholder="Enter JSON-LD schema markup"
                          value={schema}
                          onChange={(e) => setSchema(e.target.value)}
                          rows={6}
                          className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-black/20 border border-green-500/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-200 resize-none font-mono text-xs sm:text-sm"
                        />
                      </div>

                      <div className="flex justify-end">
                        <button
                          onClick={handleSeoSubmit}
                          disabled={seoLoading}
                          className={`inline-flex items-center px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 text-white font-medium rounded-xl shadow-lg hover:shadow-green-500/25 transition-all duration-200 space-x-2 text-sm sm:text-base ${
                            seoLoading ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                        >
                          {seoLoading ? (
                            <>
                              <div className="w-4 h-4 sm:w-5 sm:h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                              <span>Saving...</span>
                            </>
                          ) : (
                            <>
                              <span className="text-base sm:text-lg">💾</span>
                              <span>Save SEO Content</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'profiles' && <ProfileManagement />}
          </div>
        </div>
      </div>
    </div>
  );
}
