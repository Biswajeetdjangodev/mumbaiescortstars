// Fetch agency data server-side
async function fetchAgencyData() {
  try {
    const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
    // For server-side fetching, we'll need to handle authentication differently
    // This is a placeholder - we'll need to modify the API to support server-side auth
    const servicesResponse = await fetch(`${baseUrl}/api/services`, {
      cache: 'no-store', // Don't cache agency data
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!servicesResponse.ok) {
      console.warn('Failed to fetch services server-side:', servicesResponse.status);
      return { services: [], user: null };
    }

    const servicesData = await servicesResponse.json();
    return {
      services: servicesData.services || [],
      user: null // Will be handled client-side for auth
    };
  } catch (error) {
    console.error('Error fetching agency data server-side:', error);
    return { services: [], user: null };
  }
}

import AgencyDashboardClient from './AgencyDashboardClient';

export default async function AgencyDashboard() {
  // Fetch agency data on the server
  const { services, user } = await fetchAgencyData();

  return <AgencyDashboardClient initialServices={services} initialUser={user} />;
}
