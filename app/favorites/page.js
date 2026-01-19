// Force dynamic rendering for this page
export const dynamic = 'force-dynamic';

// Fetch favorites data server-side
async function fetchFavoritesData() {
  try {
    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
    // For server-side fetching, we'll need to handle authentication differently
    // This is a placeholder - we'll need to modify the API to support server-side auth
    const favoritesResponse = await fetch(`${baseUrl}/api/favorites`, {
      cache: 'no-store', // Don't cache favorites data
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!favoritesResponse.ok) {
      console.warn('Failed to fetch favorites server-side:', favoritesResponse.status);
      return [];
    }

    const favoritesData = await favoritesResponse.json();
    return favoritesData.map(fav => fav.service) || [];
  } catch (error) {
    console.error('Error fetching favorites server-side:', error);
    return [];
  }
}

import FavoritesPageClient from './FavoritesPageClient';

export default async function FavoritesPage() {
  // Fetch favorites data on the server
  const favorites = await fetchFavoritesData();

  return <FavoritesPageClient initialFavorites={favorites} />;
}
