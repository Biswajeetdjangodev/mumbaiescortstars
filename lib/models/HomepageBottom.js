import mongoose from "mongoose";

const HomepageBottomSchema = new mongoose.Schema({
  content: {
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
HomepageBottomSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.models.HomepageBottom || mongoose.model("HomepageBottom", HomepageBottomSchema);
