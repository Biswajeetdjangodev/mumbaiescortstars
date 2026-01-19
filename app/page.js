import HomeCard from "@/components/HomeCard";

// Force dynamic rendering to ensure fresh data on every request
export const dynamic = 'force-dynamic';

async function fetchHomepageTop() {
  try {
    const response = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'}/api/homepage-top`, {
      cache: 'no-store',
    });

    if (!response.ok) {
      console.warn('Failed to fetch homepage top data:', response.status);
      return { h1: '', seodescription: '' };
    }

    return await response.json();
  } catch (error) {
    console.warn('Error fetching homepage top data:', error);
    return { h1: '', seodescription: '' };
  }
}

async function fetchHomepageBottom() {
  try {
    const response = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'}/api/homepage-bottom`, {
      cache: 'no-store',
    });

    if (!response.ok) {
      console.warn('Failed to fetch homepage bottom data:', response.status);
      return { content: '' };
    }

    return await response.json();
  } catch (error) {
    console.warn('Error fetching homepage bottom data:', error);
    return { content: '' };
  }
}

async function fetchMetaData() {
  try {
    const response = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'}/api/meta`, {
      cache: 'no-store',
    });

    if (!response.ok) {
      console.warn('Failed to fetch meta data:', response.status);
      return {
        seotitle: '',
        seodescription: '',
        metaKeywords: [],
        canonicalUrl: '',
        robots: 'index, follow'
      };
    }

    return await response.json();
  } catch (error) {
    console.warn('Error fetching meta data:', error);
    return {
      seotitle: '',
      seodescription: '',
      metaKeywords: [],
      canonicalUrl: '',
      robots: 'index, follow'
    };
  }
}

export async function generateMetadata() {
  // Fetch meta data for page metadata
  const metaData = await fetchMetaData();

  const metadata = {
    title: metaData.seotitle || 'Default Title',
    description: metaData.seodescription || 'Default Description',
    robots: metaData.robots || 'index, follow',
    other: {},
  };

  // Add keywords if present
  if (metaData.metaKeywords && metaData.metaKeywords.length > 0) {
    metadata.other.keywords = metaData.metaKeywords.join(', ');
  }

  // Add canonical if present
  if (metaData.canonicalUrl) {
    metadata.alternates = {
      canonical: metaData.canonicalUrl,
    };
  }

  return metadata;
}

export default async function Home() {
  // Fetch SEO data from separate endpoints
  const [homepageTop, homepageBottom] = await Promise.all([
    fetchHomepageTop(),
    fetchHomepageBottom()
  ]);

  return (
    <>
      {/* Render SEO header */}
      {homepageTop && homepageTop.h1 ? (
        <div className="px-8 py-10 bg-[#33182c] md:mx-10 md:mt-10 md:rounded-xl">
          <h1 className='text-lg font-bold'>{homepageTop.h1}</h1>
          <p>{homepageTop.seodescription}</p>
        </div>
      ) : null}

      {/* Render HomeCard with server-side data fetching */}
      <HomeCard />

      {/* Render SEO footer */}
      {homepageBottom && homepageBottom.content ? (
        <div className='px-8 py-10 bg-[#33182c] md:m-10 md:rounded-xl' dangerouslySetInnerHTML={{ __html: homepageBottom.content }} />
      ) : null}
    </>
  );
}
