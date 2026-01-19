import mongoose from "mongoose";

const FavoriteSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  service: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Service",
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Compound index to ensure unique user-service pairs
FavoriteSchema.index({ user: 1, service: 1 }, { unique: true });

export default mongoose.models.Favorite || mongoose.model("Favorite", FavoriteSchema);
