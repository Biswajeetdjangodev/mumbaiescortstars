import ServiceCard from "@/components/ServiceCard";

// Force dynamic rendering to ensure fresh services data on every request
export const dynamic = 'force-dynamic';

async function getServices() {
  const res = await fetch('/api/services', {
    cache: "no-store",
  });
  return res.json();
}

async function ServicesPage() {
  const services = await getServices();
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6">
      {services.map((service) => (
        <ServiceCard key={service._id} service={service} />
      ))}
    </div>
  );
}

export default ServicesPage;
