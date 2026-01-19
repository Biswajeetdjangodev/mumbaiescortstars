'use client'
import { useState, useEffect } from 'react';
import ImageUpload from './ImageUpload';
import { useDispatch } from 'react-redux';
import { invalidateProfilesCache } from '../lib/slices/profileSlice';
import { slugify } from '../lib/utils';


export default function AdminProfileForm({ onProfileAdded, initialData }) {
const [tagInput, setTagInput] = useState('');
const [serviceInput, setServiceInput] = useState('');
  const dispatch = useDispatch();
  const [form, setForm] = useState({
    name: '',
    nationality: '',
    age: '',
    price: '',
    phone: '',
    image: '',
    gallery: ['', '', '', ''],
    description: '',
    fullDescription: '',
    tags: [],
    services: [],
    stats: {
      height: '',
      weight: '',
      bust: '',
      waist: '',
      hips: '',
      hair: '',
      eyes: ''
    },
    availability: 'Available now',
    // New fields from schema
    status: 'Pending Review',
    visibility: 'Hidden',
    username: '',
    location: '',
    dateOfBirth: '',
    servicePreferences: '',
    rateStructure: '',
    idVerificationStatus: 'Unverified',
    photoModerationStatus: 'Requires Review',
    internalNotes: '',
    lastModeratedBy: '',
    reasonForStatusChange: '',
    featuredStatus: 'None',
  });

  const [loading, setLoading] = useState(false);

  // Populate form with initial data when editing
  useEffect(() => {
    if (initialData) {
      setForm({
        name: initialData.name || '',
        nationality: initialData.nationality || '',
        age: initialData.age || '',
        price: initialData.price || '',
        phone: initialData.phone || '',
        image: initialData.image || '',
        gallery: initialData.gallery || ['', '', '', ''],
        description: initialData.description || '',
        fullDescription: initialData.fullDescription || '',
        tags: initialData.tags || [],
        services: initialData.services || [],
        stats: initialData.stats || {
          height: '',
          weight: '',
          bust: '',
          waist: '',
          hips: '',
          hair: '',
          eyes: ''
        },
        availability: initialData.availability || 'Available now',
        // New fields
        status: initialData.status || 'Pending Review',
        visibility: initialData.visibility || 'Hidden',
        username: initialData.username || '',
        location: initialData.location || '',
        dateOfBirth: initialData.dateOfBirth || '',
        servicePreferences: initialData.servicePreferences || '',
        rateStructure: initialData.rateStructure || '',
        idVerificationStatus: initialData.idVerificationStatus || 'Unverified',
        photoModerationStatus: initialData.photoModerationStatus || 'Requires Review',
        internalNotes: initialData.internalNotes || '',
        lastModeratedBy: initialData.lastModeratedBy || '',
        reasonForStatusChange: initialData.reasonForStatusChange || '',
        featuredStatus: initialData.featuredStatus || 'None',
      });
    }
  }, [initialData]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const handleGalleryChange = (index, value) => {
    const newGallery = [...form.gallery];
    newGallery[index] = value;
    setForm(prev => ({ ...prev, gallery: newGallery }));
  };



  const handleStatsChange = (field, value) => {
    setForm(prev => ({
      ...prev,
      stats: { ...prev.stats, [field]: value }
    }));
  };

  const handleTagAdd = (e) => {
    if (e.key === 'Enter' && tagInput.trim()) {
      e.preventDefault();
      const newTag = tagInput.trim().toLowerCase().replace(/\s+/g, '-');
      if (!form.tags.includes(newTag)) {
        setForm(prev => ({ ...prev, tags: [...prev.tags, newTag] }));
      }
      setTagInput('');
    }
  };

  const handleServiceAdd = (e) => {
    if (e.key === 'Enter' && serviceInput.trim()) {
      e.preventDefault();
      const newService = serviceInput.trim();
      if (!form.services.includes(newService)) {
        setForm(prev => ({ ...prev, services: [...prev.services, newService] }));
      }
      setServiceInput('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const token = localStorage.getItem('token');
      const isEditing = !!initialData;
      const method = isEditing ? 'PUT' : 'POST';

      // Generate slug if not present (for new profiles) or preserve existing one
      const slug = initialData?.slug || slugify(form.name);
      const requestBody = isEditing ? { ...form, id: initialData._id, slug } : { ...form, slug };

      const response = await fetch('/api/services', {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        const updatedProfile = await response.json();
        alert(`Profile ${isEditing ? 'updated' : 'created'} successfully!`);
        if (isEditing) {
          dispatch(invalidateProfilesCache());
        }
        if (onProfileAdded) onProfileAdded(updatedProfile);

        // Reset form only when creating new profile
        if (!isEditing) {
          setForm({
            name: '',
            nationality: '',
            age: '',
            price: '',
            phone: '',
            image: '',
            gallery: ['', '', '', ''],
            description: '',
            fullDescription: '',
            tags: [],
            services: [],
            stats: {
              height: '',
              weight: '',
              bust: '',
              waist: '',
              hips: '',
              hair: '',
              eyes: ''
            },
            availability: 'Available now',
            status: 'Pending Review',
            visibility: 'Hidden',
            username: '',
            location: '',
            dateOfBirth: '',
            servicePreferences: '',
            rateStructure: '',
            idVerificationStatus: 'Unverified',
            photoModerationStatus: 'Requires Review',
            internalNotes: '',
            lastModeratedBy: '',
            reasonForStatusChange: '',
            featuredStatus: 'None',
          });
        }
      } else {
        alert(`Failed to ${isEditing ? 'update' : 'create'} profile`);
      }
    } catch (error) {
      console.error(`Error ${initialData ? 'updating' : 'creating'} profile:`, error);
      alert(`Error ${initialData ? 'updating' : 'creating'} profile`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-linear-to-br from-purple-800/20 to-pink-800/20 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-8 shadow-xl">
      <div className="flex items-center space-x-3 mb-6">
        <div className="w-10 h-10 bg-linear-to-r from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
          <span className="text-white text-lg">{initialData ? '✏️' : '✨'}</span>
        </div>
        <h3 className="text-2xl font-bold text-white">{initialData ? 'Edit Profile' : 'Create New Profile'}</h3>
      </div>
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Basic Info */}
        <div className="bg-black/20 rounded-xl p-6 border border-purple-500/20">
          <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center">
            <span className="mr-2">👤</span>
            Basic Information
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <input
              type="text"
              name="name"
              placeholder="Full Name *"
              value={form.name}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
              required
            />
            <input
              type="text"
              name="username"
              placeholder="Username / Display Name"
              value={form.username}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            />
            <input
              type="text"
              name="nationality"
              placeholder="Nationality"
              value={form.nationality}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            />
            <input
              type="number"
              name="age"
              placeholder="Age"
              value={form.age}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            />
             <input
              type="date"
              name="dateOfBirth"
              placeholder="Date of Birth"
              value={form.dateOfBirth}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            />
            <input
              type="text"
              name="price"
              placeholder="Starting Price (e.g., 300)"
              value={form.price}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            />
            <input
              type="tel"
              name="phone"
              placeholder="Phone Number"
              value={form.phone}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            />
            <input
              type="text"
              name="location"
              placeholder="Location / City"
              value={form.location}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            />
            <select
              name="availability"
              value={form.availability}
              onChange={handleChange}
              className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
            >
              <option value="Available now">Available now</option>
              <option value="Busy">Currently Busy</option>
              <option value="Offline">Offline</option>
            </select>
            <div className="col-span-2">
              <label className="block text-sm font-medium text-purple-300 mb-2">Tags</label>
              <input
                type="text"
                placeholder="Type a tag and press Enter to add"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={handleTagAdd}
                className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
              />
              {form.tags.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {form.tags.map(tag => (
                    <span key={tag} className="bg-purple-500/20 text-purple-300 text-xs px-2 py-1 rounded-full border border-purple-500/30">
                      {tag.replace('-', ' ')}
                      <button
                        type="button"
                        onClick={() => setForm(prev => ({ ...prev, tags: prev.tags.filter(t => t !== tag) }))}
                        className="ml-1 text-purple-400 hover:text-purple-200"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="col-span-2">
              <label className="block text-sm font-medium text-purple-300 mb-2">Services</label>
              <input
                type="text"
                placeholder="Type a service and press Enter to add"
                value={serviceInput}
                onChange={(e) => setServiceInput(e.target.value)}
                onKeyDown={handleServiceAdd}
                className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
              />
              {form.services.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {form.services.map(service => (
                    <span key={service} className="bg-green-500/20 text-green-300 text-xs px-2 py-1 rounded-full border border-green-500/30">
                      {service}
                      <button
                        type="button"
                        onClick={() => setForm(prev => ({ ...prev, services: prev.services.filter(s => s !== service) }))}
                        className="ml-1 text-green-400 hover:text-green-200"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Status & Visibility */}
        <div className="bg-black/20 rounded-xl p-6 border border-purple-500/20">
            <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center">
                <span className="mr-2">🚦</span>
                Status & Visibility
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <select
                name="status"
                value={form.status}
                onChange={handleChange}
                className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
                >
                <option value="Pending Review">Pending Review</option>
                <option value="Active">Active</option>
                <option value="Inactive">Inactive</option>
                </select>
                <select
                name="visibility"
                value={form.visibility}
                onChange={handleChange}
                className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
                >
                <option value="Hidden">Hidden</option>
                <option value="Visible">Visible</option>
                </select>
            </div>
        </div>

        {/* Main Image Upload */}
        <ImageUpload
          label="Main Profile Image"
          currentImage={form.image}
          onImageUpload={(image) => setForm(prev => ({ ...prev, image }))}
        />

        {/* Gallery Images Upload */}
        <ImageUpload
          label="Gallery Images (Up to 4)"
          currentImage={form.gallery.filter(img => img !== '')}
          onImageUpload={(images) => {
            const galleryArray = [...images];
            while (galleryArray.length < 4) {
              galleryArray.push('');
            }
            setForm(prev => ({ ...prev, gallery: galleryArray.slice(0, 4) }));
          }}
          multiple={true}
        />

        {/* Descriptions */}
        <div className="bg-black/20 rounded-xl p-6 border border-purple-500/20">
          <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center">
            <span className="mr-2">📝</span>
            Profile Descriptions
          </h4>
          <div className="space-y-4">
            <textarea
              name="description"
              placeholder="Short Description (appears on profile cards)"
              value={form.description}
              onChange={handleChange}
              className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200 resize-none"
              rows={3}
            />
            <textarea
              name="fullDescription"
              placeholder="Detailed Description (appears on profile page)"
              value={form.fullDescription}
              onChange={handleChange}
              className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200 resize-none"
              rows={6}
            />
            <textarea
              name="servicePreferences"
              placeholder="Service Preferences / Offerings"
              value={form.servicePreferences}
              onChange={handleChange}
              className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200 resize-none"
              rows={4}
            />
            <textarea
              name="rateStructure"
              placeholder="Rate Structure (e.g., half-hour, one hour, overnight)"
              value={form.rateStructure}
              onChange={handleChange}
              className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200 resize-none"
              rows={4}
            />
          </div>
        </div>

        {/* Physical Stats */}
        <div className="bg-black/20 rounded-xl p-6 border border-purple-500/20">
          <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center">
            <span className="mr-2">📏</span>
            Physical Statistics
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {Object.entries(form.stats).map(([key, value]) => (
              <input
                key={key}
                type="text"
                placeholder={key.charAt(0).toUpperCase() + key.slice(1)}
                value={value}
                onChange={(e) => handleStatsChange(key, e.target.value)}
                className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
              />
            ))}
          </div>
        </div>

        {/* Verification & Moderation */}
        <div className="bg-black/20 rounded-xl p-6 border border-purple-500/20">
            <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center">
                <span className="mr-2">🛡️</span>
                Verification & Moderation
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <select
                name="idVerificationStatus"
                value={form.idVerificationStatus}
                onChange={handleChange}
                className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
                >
                    <option value="Unverified">Unverified</option>
                    <option value="Documents Pending">Documents Pending</option>
                    <option value="Verified">Verified</option>
                </select>
                <select
                name="photoModerationStatus"
                value={form.photoModerationStatus}
                onChange={handleChange}
                className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
                >
                    <option value="Requires Review">Requires Review</option>
                    <option value="Some Pending">Some Pending</option>
                    <option value="All Approved">All Approved</option>
                </select>
                 <select
                name="featuredStatus"
                value={form.featuredStatus}
                onChange={handleChange}
                className="p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
                >
                    <option value="None">None</option>
                    <option value="Featured">Featured</option>
                    <option value="Priority">Priority</option>
                </select>
            </div>
            <div className="mt-4 space-y-4">
                <textarea
                    name="internalNotes"
                    placeholder="Internal Notes / Admin Memo"
                    value={form.internalNotes}
                    onChange={handleChange}
                    className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200 resize-none"
                    rows={4}
                />
                <textarea
                    name="reasonForStatusChange"
                    placeholder="Reason for Suspension/Ban"
                    value={form.reasonForStatusChange}
                    onChange={handleChange}
                    className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200 resize-none"
                    rows={3}
                />
                 <input
                    type="text"
                    name="lastModeratedBy"
                    placeholder="Last Moderated By"
                    value={form.lastModeratedBy}
                    onChange={handleChange}
                    className="w-full p-3 bg-black/30 border border-purple-500/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200"
                />
            </div>
        </div>

        <div className="flex justify-end pt-4">
          <button
            type="submit"
            disabled={loading}
            className="bg-linear-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-8 py-4 rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-purple-500/25 flex items-center space-x-2"
          >
            {loading ? (
              <>
                <div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                <span>{initialData ? 'Updating Profile...' : 'Creating Profile...'}</span>
              </>
            ) : (
              <>
                <span className="text-lg">{initialData ? '💾' : '✨'}</span>
                <span>{initialData ? 'Update Profile' : 'Create Profile'}</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
