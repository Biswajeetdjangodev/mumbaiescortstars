'use client';
import { useEffect, memo } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useDispatch, useSelector } from 'react-redux';
import { fetchFavorites, toggleFavorite, toggleFavoriteLocal } from '../../lib/slices/profileSlice';
import { useHydrated } from '../../lib/hooks/useHydrated';

const FavoriteCard = memo(({ service, onRemove }) => (
  <div className="bg-linear-to-b from-gray-900 to-gray-800 backdrop-blur-lg border border-gray-700 rounded-xl p-6 shadow-lg hover:shadow-2xl transition transform hover:-translate-y-2 hover:scale-[1.02]">
    <div className="flex items-center space-x-4">
      <Image
        src={service.image || '/default-avatar.png'}
        alt={service.name}
        width={64}
        height={64}
        className="w-16 h-16 rounded-full object-cover border-2 border-purple-500"
        loading="lazy"
      />
      <div>
        <h2 className="text-xl font-bold text-white">{service.name}</h2>
        <p className="text-gray-400 text-sm">{service.category || "Uncategorized"}</p>
      </div>
    </div>

    <p className="text-gray-300 mt-4 line-clamp-3">{service.description || "No description available."}</p>

    <div className="flex justify-between mt-5">
      <Link href={`/profile/${service.createdBy}`} className="w-full mr-2">
        <button className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 rounded-lg transition">
          View Details
        </button>
      </Link>
      <button onClick={() => onRemove(service._id)} className="w-full ml-2 bg-red-600 hover:bg-red-700 text-white font-semibold py-2 rounded-lg transition">
        Remove
      </button>
    </div>
  </div>
));

FavoriteCard.displayName = 'FavoriteCard';

export default function FavoritesPageClient({ initialFavorites }) {
  const dispatch = useDispatch();
  const { favorites, favoritesLoading, error } = useSelector((state) => state.profile);
  const isHydrated = useHydrated();

  // Use server-fetched data initially, then switch to Redux state when client-side data is loaded
  const displayFavorites = favorites.length > 0 ? favorites : initialFavorites;

  useEffect(() => {
    if (isHydrated) {
      dispatch(fetchFavorites());
    }
  }, [dispatch, isHydrated]);

  const handleRemove = (serviceId) => {
    const token = localStorage.getItem('token');
    if (token) {
      dispatch(toggleFavorite({ serviceId }));
    } else {
      dispatch(toggleFavoriteLocal(displayFavorites.find(fav => fav._id === serviceId)));
    }
  };

  if (!isHydrated) {
    return (
      <div className="flex justify-center items-center">
        <div className="text-white text-2xl font-semibold animate-pulse">Loading favorites...</div>
      </div>
    );
  }

  if (favoritesLoading && !initialFavorites.length) {
    return (
      <div className="flex justify-center items-center">
        <div className="text-white text-2xl font-semibold animate-pulse">Loading favorites...</div>
      </div>
    );
  }

  return (
    <div className=" px-10">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold text-white">⭐ Your Favorites</h1>
        <p className="text-gray-400 mt-2">Here are the services you've saved</p>
      </div>

      {displayFavorites.length > 0 ? (
        <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3 max-w-6xl mx-auto">
          {displayFavorites.map((service) => (
            <FavoriteCard key={service._id} service={service} onRemove={handleRemove} />
          ))}
        </div>
      ) : (
        <div className="text-center text-gray-300 text-lg mt-20">
          No favorites found 💔
        </div>
      )}
    </div>
  );
}
