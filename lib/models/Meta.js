import mongoose from "mongoose";

const MetaSchema = new mongoose.Schema({
  seotitle: {
    type: String,
    required: false,
    default: ''
  },
  seodescription: {
    type: String,
    required: false,
    default: ''
  },
  metaKeywords: {
    type: [String],
    required: false,
    default: []
  },
  canonicalUrl: {
    type: String,
    required: false,
    default: ''
  },
  robots: {
    type: String,
    required: false,
    default: 'index, follow'
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
MetaSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.models.Meta || mongoose.model("Meta", MetaSchema);
