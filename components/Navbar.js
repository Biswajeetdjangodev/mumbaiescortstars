'use client'
import { useState, useEffect } from 'react';
import { Heart, Menu, X } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export default function Navbar() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [favorites, setFavorites] = useState([]);
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  // You should abstract this logic to avoid repetition
  const fetchUserData = async () => {
    try {
      if (typeof window === 'undefined' || !window.localStorage) {
        setIsLoading(false);
        return;
      }

      const token = localStorage.getItem('token');
      if (!token) {
        setIsLoading(false);
        return;
      }

      const response = await fetch('/api/auth/verify', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      } else {
        localStorage.removeItem('token');
        localStorage.removeItem('role');
      }
    } catch (error) {
      console.error('Error checking auth:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchFavorites = async () => {
    try {
      if (typeof window === 'undefined' || !window.localStorage) return;

      const token = localStorage.getItem('token');
      if (!token) {
        setFavorites([]);
        return;
      }

      const response = await fetch('/api/favorites', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setFavorites(data);
      } else if (response.status === 401) {
        console.log('User not authenticated, clearing favorites');
        setFavorites([]);
      } else {
        console.error('Failed to fetch favorites:', response.status, response.statusText);
      }
    } catch (error) {
      console.error('Error fetching favorites:', error);
      setFavorites([]);
    }
  };

  useEffect(() => {
    fetchUserData();
    fetchFavorites();

    // Listen for auth state changes
    const handleAuthStateChange = () => {
      fetchUserData();
      fetchFavorites();
    };

    window.addEventListener('authStateChanged', handleAuthStateChange);
    
    return () => {
      window.removeEventListener('authStateChanged', handleAuthStateChange);
    };
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    setUser(null);
    setFavorites([]);
    router.push('/');
  };

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  // Determine the correct dashboard link based on the user's role
  const getDashboardLink = () => {
    if (!user) return '/';
    if (user.role === 'admin') {
      return '/dashboard/role-based';
    }
    return '/dashboard';
  };

  const dashboardLink = getDashboardLink();

  return (
    <header className="bg-[#33182c] text-white shadow-lg">
      <div className="w-full max-w-6xl mx-auto px-4 sm:px-3 py-2">
        <div className="flex items-center justify-between h-16 w-full">
          <div className="flex items-center space-x-2">
            <Link href="/">
              <h2 className="text-xl md:text-2xl font-bold tracking-wide">
                MUMBAI ESCORT
              </h2>
            </Link>
            <div className="hidden md:flex items-center space-x-1 ml-4">
              <div className="w-px h-6 bg-pink-400 mx-2"></div>
              {[1, 2, 3, 4, 5].map((star) => (
                <svg
                  key={star}
                  className="w-4 h-4 text-pink-400 fill-current"
                  viewBox="0 0 20 20"
                >
                  <path d="M10 15l-5.878 3.09 1.123-6.545L.489 6.91l6.572-.955L10 0l2.939 5.955 6.572.955-4.756 4.635 1.123 6.545z" />
                </svg>
              ))}
              <div className="w-px h-6 bg-pink-400 mx-2"></div>
            </div>
          </div>

          <nav className="hidden lg:flex items-center space-x-6">
            <div>
              <a className="flex items-center space-x-2 text-gray-200 hover:text-white transition-colors cursor-pointer" href="/favorites">
                <Heart className="w-5 h-5" />
                <span>Favorites ({favorites.length})</span>
              </a>
            </div>

            {user ? (
              <div className="flex items-center space-x-4">
                <span className="text-gray-200">Welcome, {user.email}</span>
                <Link
                  href={dashboardLink}
                  className="text-gray-200 hover:text-white transition-colors font-medium"
                >
                  DASHBOARD
                </Link>
                <button
                  onClick={handleLogout}
                  className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-md font-semibold transition-all duration-200"
                >
                  LOGOUT
                </button>
              </div>
            ) : (
              <>
                <Link
                  href="/register"
                  className="text-gray-200 hover:text-white transition-colors font-medium"
                >
                  LISTING
                </Link>
                <Link
                  href="/login"
                  className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 px-6 py-2 rounded-md font-semibold transition-all duration-200 shadow-lg hover:shadow-xl"
                >
                  LOGIN
                </Link>
              </>
            )}
          </nav>

          <button
            onClick={toggleMobileMenu}
            className="lg:hidden p-2 rounded-md hover:bg-purple-700 transition-colors"
          >
            {isMobileMenuOpen ? (
              <X className="w-6 h-6" />
            ) : (
              <Menu className="w-6 h-6" />
            )}
          </button>
        </div>

        <div className="md:hidden flex items-center justify-center space-x-1 pb-2">
          <div className="w-8 h-px bg-pink-400"></div>
          {[1, 2, 3, 4, 5].map((star) => (
            <svg
              key={star}
              className="w-4 h-4 text-pink-400 fill-current"
              viewBox="0 0 20 20"
            >
              <path d="M10 15l-5.878 3.09 1.123-6.545L.489 6.91l6.572-.955L10 0l2.939 5.955 6.572.955-4.756 4.635 1.123 6.545z" />
            </svg>
          ))}
          <div className="w-8 h-px bg-pink-400"></div>
        </div>
      </div>

      {isMobileMenuOpen && (
        <div className="lg:hidden bg-purple-900/95 backdrop-blur-sm border-t border-purple-700">
          <div className="w-full px-4 py-4 space-y-4">
            <Link href="/favorites" onClick={() => setIsMobileMenuOpen(false)} className="flex items-center space-x-2 text-gray-200 hover:text-white transition-colors cursor-pointer py-2">
              <Heart className="w-5 h-5" />
              <span>Favorites ({favorites.length})</span>
            </Link>

            {user ? (
              <>
                <div className="text-gray-200 py-2">
                  Welcome, {user.email}
                </div>
                <Link
                  href={dashboardLink}
                  className="block text-gray-200 hover:text-white transition-colors font-medium py-2"
                  onClick={() => setIsMobileMenuOpen(false)}
                >
                  DASHBOARD
                </Link>
                <button
                  onClick={() => {
                    handleLogout();
                    setIsMobileMenuOpen(false);
                  }}
                  className="block w-full bg-red-600 hover:bg-red-700 px-6 py-3 rounded-md font-semibold transition-all duration-200 text-center"
                >
                  LOGOUT
                </button>
              </>
            ) : (
              <>
                <Link
                  href="/register"
                  className="block text-gray-200 hover:text-white transition-colors font-medium py-2"
                  onClick={() => setIsMobileMenuOpen(false)}
                >
                  LISTING
                </Link>
                <Link
                  href="/login"
                  className="block bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 px-6 py-3 rounded-md font-semibold transition-all duration-200 shadow-lg text-center"
                  onClick={() => setIsMobileMenuOpen(false)}
                >
                  LOGIN
                </Link>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
}