import mongoose from "mongoose";

const HomepageTopSchema = new mongoose.Schema({
  h1: {
    type: String,
    required: false,
    default: ''
  },
  seodescription: {
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
HomepageTopSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.models.HomepageTop || mongoose.model("HomepageTop", HomepageTopSchema);
