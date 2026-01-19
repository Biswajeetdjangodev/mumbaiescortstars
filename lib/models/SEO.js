import mongoose from "mongoose";

const SEOSchema = new mongoose.Schema({
  page: {
    type: String,
    required: true,
    unique: true
  },
  seotitle: {
    type: String,
    required: false
  },
  seodescription: {
    type: String,
    required: false
  },
  h1: {
    type: String,
    required: false
  },
  content: {
    type: String,
    required: false
  },
  metaKeywords: {
    type: [String],
    required: false,
    default: []
  },
  canonicalUrl: {
    type: String,
    required: false
  },
  robots: {
    type: String,
    required: false,
    default: 'index, follow'
  },
  ogTitle: {
    type: String,
    required: false
  },
  ogDescription: {
    type: String,
    required: false
  },
  ogImage: {
    type: String,
    required: false
  },
  twitterTitle: {
    type: String,
    required: false
  },
  twitterDescription: {
    type: String,
    required: false
  },
  twitterImage: {
    type: String,
    required: false
  },
  schema: {
    type: String,
    required: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt field before saving
SEOSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.models.SEO || mongoose.model("SEO", SEOSchema);
