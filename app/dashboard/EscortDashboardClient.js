'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import LoadingSpinner from './components/LoadingSpinner';
import DashboardHeader from './components/DashboardHeader';
import TabNavigation from './components/TabNavigation';
import OverviewTab from './components/OverviewTab';
import ProfilesTab from './components/ProfilesTab';
import AnalyticsTab from './components/AnalyticsTab';

export default function EscortDashboardClient({ initialServices, initialUser }) {
  const [user, setUser] = useState(initialUser || null);
  const [services, setServices] = useState(initialServices || []);
  const [loading, setLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
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

          // Verify user is escort
          if (userData.role !== 'escort') {
            router.push('/');
            return;
          }

          setUser(userData);

          // Fetch services with authentication to get filtered results
          const servicesResponse = await fetch('/api/services', {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });

          if (servicesResponse.ok) {
            const servicesData = await servicesResponse.json();
            setServices(servicesData.services || []);
          }
        } else {
          router.push('/login');
        }
      } catch (error) {
        console.error('Error fetching data:', error);
        router.push('/login');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    router.push('/login');
  };

  const handleAddProfileClick = () => {
    setActiveTab('profiles');
    setShowAddForm(true);
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

  const tabs = [
    { id: 'overview', label: 'Dashboard Overview', shortLabel: 'Overview', icon: '📊', color: 'from-purple-600 to-pink-600' },
    { id: 'profiles', label: 'My Profiles', shortLabel: 'Profiles', icon: '💎', color: 'from-pink-600 to-purple-600' },
    { id: 'analytics', label: 'Analytics', shortLabel: 'Analytics', icon: '📈', color: 'from-blue-600 to-purple-600' }
  ];

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="min-h-screen bg-linear-to-br from-purple-900 via-gray-900 to-black">
      <DashboardHeader user={user} onLogout={handleLogout} />

      <div className="max-w-7xl mx-auto px-2 sm:px-4 lg:px-8 py-4 sm:py-8">
        <TabNavigation
          tabs={tabs}
          activeTab={activeTab}
          onTabChange={setActiveTab}
        />

        <div className="p-4 sm:p-8">
          {activeTab === 'overview' && (
            <OverviewTab
              services={services}
              onAddProfileClick={handleAddProfileClick}
            />
          )}

          {activeTab === 'profiles' && (
            <ProfilesTab
              services={services}
              showAddForm={showAddForm}
              onAddProfile={setShowAddForm}
              refreshServices={refreshServices}
            />
          )}

          {activeTab === 'analytics' && <AnalyticsTab />}
        </div>
      </div>
    </div>
  );
}
