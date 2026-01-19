'use client'
import { useState, useRef, useEffect } from 'react';
import Image from 'next/image';

export default function ImageUpload({ onImageUpload, currentImage, label = "Upload Image", multiple = false }) {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadedImages, setUploadedImages] = useState(currentImage ? (Array.isArray(currentImage) ? currentImage : [currentImage]) : []);
  const fileInputRef = useRef(null);

  useEffect(() => {
    setUploadedImages(currentImage ? (Array.isArray(currentImage) ? currentImage : [currentImage]) : []);
  }, [currentImage]);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    
    const files = Array.from(e.dataTransfer.files);
    handleFiles(files);
  };

  const handleFileSelect = (e) => {
    const files = Array.from(e.target.files);
    handleFiles(files);
  };

  const handleFiles = async (files) => {
    const validFiles = files.filter(file => file.type.startsWith('image/'));
    
    if (validFiles.length === 0) {
      alert('Please select valid image files');
      return;
    }

    const uploadPromises = validFiles.map(file => uploadImage(file));
    
    try {
      const uploadedUrls = await Promise.all(uploadPromises);
      
      if (multiple) {
        const newImages = [...uploadedImages, ...uploadedUrls].slice(0, 4); // Limit to 4 images
        setUploadedImages(newImages);
        onImageUpload(newImages);
      } else {
        setUploadedImages([uploadedUrls[0]]);
        onImageUpload(uploadedUrls[0]);
      }
    } catch (error) {
      console.error('Error uploading images:', error);
      alert('Error uploading images. Please try again.');
    }
  };

  const uploadImage = async (file) => {
    const formData = new FormData();
    formData.append('files', file);

    const response = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error('Upload failed');
    }

    const result = await response.json();
    return result.images[0].url;
  };

  const removeImage = (index) => {
    if (multiple) {
      const newImages = uploadedImages.filter((_, i) => i !== index);
      setUploadedImages(newImages);
      onImageUpload(newImages);
    } else {
      setUploadedImages([]);
      onImageUpload('');
    }
  };

  const openFileDialog = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="space-y-4">
      <label className="block text-sm font-medium text-gray-300 mb-2">
        {label}
      </label>
      
      {/* Upload Area */}
      <div
        className={`border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 cursor-pointer ${
          isDragging
            ? 'border-purple-500 bg-purple-500/10'
            : 'border-gray-600 hover:border-purple-500 hover:bg-purple-500/5'
        }`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={openFileDialog}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          multiple={multiple}
          onChange={handleFileSelect}
          className="hidden"
        />
        
        <div className="flex flex-col items-center space-y-4">
          <div className="w-16 h-16 bg-gradient-to-r from-purple-500/20 to-pink-500/20 rounded-full flex items-center justify-center">
            <span className="text-2xl">📸</span>
          </div>
          <div>
            <p className="text-white font-medium">Click to upload or drag and drop</p>
            <p className="text-gray-400 text-sm">PNG, JPG, JPEG up to 10MB</p>
            {multiple && <p className="text-purple-400 text-xs">You can upload up to 4 images</p>}
          </div>
        </div>
      </div>

      {/* Image Preview */}
      {uploadedImages.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {uploadedImages.map((image, index) => (
            <div key={index} className="relative group">
              <Image
                src={image}
                alt={`Upload ${index + 1}`}
                width={300} // Placeholder width, adjust as needed
                height={128} // Corresponds to h-32 (8rem * 16px/rem = 128px)
                className="w-full h-32 object-cover rounded-lg border border-gray-600"
              />
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  removeImage(index);
                }}
                className="absolute -top-2 -right-2 w-6 h-6 bg-red-500 hover:bg-red-600 text-white rounded-full flex items-center justify-center text-xs transition-colors opacity-0 group-hover:opacity-100"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
