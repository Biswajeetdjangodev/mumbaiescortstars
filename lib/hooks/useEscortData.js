import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

export function useEscortData() {
  const [user, setUser] = useState(null);
  const [services, setServices] = useState([]);
  const [loading, setLoading] = useState(true);
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
            setServices(servicesData);
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
        setServices(data);
      }
    } catch (error) {
      console.error('Error refreshing services:', error);
    }
  };

  return { user, services, loading, refreshServices };
}
