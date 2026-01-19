import mongoose from "mongoose";

const ServiceSchema = new mongoose.Schema({
  name: String,
  slug: { type: String, unique: true, sparse: true }, // Add slug field for fast lookups
  description: String,
  price: { type: Number, default: 0 },
  image: String,
  nationality: String,
  phone: String,
  gallery: [String],
  fullDescription: String,
  tags: [String],
  services: [String],
  stats: {
    height: String,
    weight: String,
    bust: String,
    waist: String,
    hips: String,
    hair: String,
    eyes: String
  },
  availability: String,
  
  // New fields from form
  status: { 
    type: String, 
    enum: ['Active', 'Inactive', 'Pending Review'], 
    default: 'Pending Review' 
  },
  visibility: { 
    type: String, 
    enum: ['Visible', 'Hidden'], 
    default: 'Hidden' 
  },
  username: { type: String },
  location: String,
  dateOfBirth: Date,
  servicePreferences: String,
  rateStructure: String,
  idVerificationStatus: {
    type: String,
    enum: ['Verified', 'Unverified', 'Documents Pending'],
    default: 'Unverified'
  },
  photoModerationStatus: {
    type: String,
    enum: ['All Approved', 'Some Pending', 'Requires Review'],
    default: 'Requires Review'
  },
  internalNotes: String,
  lastModeratedBy: String,
  reasonForStatusChange: String,
  featuredStatus: { type: String, default: 'None' },

  // User tracking fields for role-based access
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  agencyName: String, // For filtering agency profiles
  creatorRole: {
    type: String,
    enum: ["admin", "agency", "escort"],
    required: true
  }
}, {
  timestamps: true // Adds createdAt and updatedAt
});

// Indexes for performance
ServiceSchema.index({ createdBy: 1 });
ServiceSchema.index({ name: 1 });
ServiceSchema.index({ status: 1 });
ServiceSchema.index({ visibility: 1 });
ServiceSchema.index({ creatorRole: 1 });
ServiceSchema.index({ createdAt: -1 }); // For sorting by newest

export default mongoose.models.Service || mongoose.model("Service", ServiceSchema);
