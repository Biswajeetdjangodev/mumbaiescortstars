import mongoose from "mongoose";

const LayoutSchema = new mongoose.Schema({
  title: {
    type: String,
    required: false,
    default: ''
  },
  description: {
    type: String,
    required: false,
    default: ''
  }
}, { timestamps: true });

// Update the updatedAt field before saving
LayoutSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.models.Layout || mongoose.model("Layout", LayoutSchema);
