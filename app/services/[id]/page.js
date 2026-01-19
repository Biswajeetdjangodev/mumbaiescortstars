import { notFound } from "next/navigation";
import ServiceCard from "@/components/ServiceCard";

async function getService(id) {
  const res = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL}/api/services/${id}`, {
    cache: "no-store",
  });
  if (!res.ok) {
    return null;
  }
  return res.json();
}

async function ServiceDetailPage({ params }) {
  const { id } = params;
  const service = await getService(id);

  if (!service) {
    notFound();
  }

  return (
    <div className="p-6">
      <ServiceCard service={service} detailed={true} />
    </div>
  );
}

export default ServiceDetailPage;
