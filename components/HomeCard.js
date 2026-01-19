// Fetch profiles server-side with dynamic caching
async function fetchProfilesData(page = 1, limit = 20) {
  try {
    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
    const response = await fetch(`${baseUrl}/api/services?page=${page}&limit=${limit}`, {
      cache: 'no-store', // Don't cache server-side to ensure fresh data
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch profiles: ${response.status}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching profiles server-side:', error);
    // Return empty data instead of throwing to prevent page crash
    return { services: [], pagination: { page: 1, limit: 20, total: 0, totalPages: 0, hasNext: false, hasPrev: false } };
  }
}

import ClientHomeCard from './ClientHomeCard';

export default async function HomeCard() {
  // Fetch initial profiles on the server
  const data = await fetchProfilesData(1, 20);

  return (
    <ClientHomeCard
      initialProfiles={data.services || []}
      initialPagination={data.pagination || { page: 1, limit: 20, total: 0, totalPages: 0, hasNext: false, hasPrev: false }}
    />
  );
}
