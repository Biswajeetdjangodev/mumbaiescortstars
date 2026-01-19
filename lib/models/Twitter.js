import mongoose from "mongoose";

const TwitterSchema = new mongoose.Schema({
  twitterTitle: {
    type: String,
    required: false,
    default: ''
  },
  twitterDescription: {
    type: String,
    required: false,
    default: ''
  },
  twitterImage: {
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
TwitterSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.models.Twitter || mongoose.model("Twitter", TwitterSchema);
