'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import AdminDashboard from '../AdminDashboard';
import EscortDashboard from '../EscortDashboard';
import AgencyDashboard from '../AgencyDashboard';

export default function RoleBasedDashboard() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        router.push('/login');
        return;
      }

      try {
        const response = await fetch('/api/auth/verify', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const userData = await response.json();
          setUser(userData);
        } else {
          router.push('/login');
        }
      } catch (error) {
        console.error('Auth check error:', error);
        router.push('/login');
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []); // Remove router dependency to prevent re-renders

  if (loading) {
    return <div className="min-h-screen bg-gray-100 p-8 flex items-center justify-center text-center">Loading...</div>;
  }

  if (!user) {
    return <div className="min-h-screen bg-gray-100 p-8">Please log in to access the dashboard.</div>;
  }

  return (
    <div className="h-full bg-gray-100">
      {user.role === "admin" && <AdminDashboard />}
      {user.role === "escort" && <EscortDashboard />}
      {user.role === "agency" && <AgencyDashboard />}
      {user.role === "visitor" && (
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Visitor Dashboard</h2>
          <p className="text-gray-600">View your favorites and account settings.</p>
        </div>
      )}
      {user.role === "landlord" && (
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Landlord Dashboard</h2>
          <p className="text-gray-600">Manage your property listings and bookings.</p>
        </div>
      )}
    </div>
  );
}
