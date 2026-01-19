import Image from "next/image";
import Link from "next/link";

export default function ServiceCard({ service }) {
  return (
    <div className="border rounded-lg shadow hover:shadow-lg transition p-4">
      <Image
        src={service.image || "/images/placeholder.jpg"}
        alt={service.name}
        width={400}
        height={250}
        className="rounded-lg"
      />
      <h2 className="text-xl font-semibold mt-3">{service.name}</h2>
      <p className="text-gray-600">{service.description}</p>
      <p className="text-blue-600 font-bold mt-2">${service.price}</p>
      <Link href={`/profile/${service.createdBy}`}>
        <button className="w-full mt-4 bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 rounded-lg transition">
          View Details
        </button>
      </Link>
    </div>
  );
}