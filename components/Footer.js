// Footer.js
'use client';
import Link from 'next/link';
import { useState, useEffect } from 'react';

export default function Footer() {
  const [tags, setTags] = useState([]);

  useEffect(() => {
    const fetchTags = async () => {
      try {
        const response = await fetch('/api/tags');
        if (response.ok) {
          const data = await response.json();
          setTags(data);
        }
      } catch (error) {
        console.error('Error fetching tags:', error);
      }
    };
    fetchTags();
  }, []);


  return (
    <footer className="bg-[#33182c] rounded-xl px-8 py-10 md:m-10">
     
      {/* Popular Tags Section */}
      <div className="mb-8">
        {/* <h3 className="text-[#bb86fc] text-base font-medium mb-4">Popular Tags:</h3> */}
        <div className="flex flex-wrap gap-3">
          {tags.map((tag, index) => (
            <Link
              key={index}
              href={`/tags/${tag}`}
              className="text-[#e0e0e0] text-sm hover:text-[#bb86fc] transition-all duration-300 py-1 relative after:absolute after:bottom-0 after:left-0 after:w-0 after:h-0.5 after:bg-[#bb86fc] after:transition-all after:duration-300 hover:after:w-full"
            >
              {tag}
            </Link>
          ))}
        </div>
      </div>

      {/* Copyright Section */}
      <div className="text-[#999999] text-sm">
        © 2026 All rights reserved.
      </div>
    </footer>
  );
}