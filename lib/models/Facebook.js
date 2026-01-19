import mongoose from "mongoose";

const FacebookSchema = new mongoose.Schema({
  ogTitle: {
    type: String,
    required: false,
    default: ''
  },
  ogDescription: {
    type: String,
    required: false,
    default: ''
  },
  ogImage: {
    type: String,
    required: false,
    default: ''
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
FacebookSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.models.Facebook || mongoose.model("Facebook", FacebookSchema);
