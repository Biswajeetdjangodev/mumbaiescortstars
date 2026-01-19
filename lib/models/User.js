import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: String,
  role: {
    type: String,
    enum: ["escort", "agency", "landlord", "visitor", "admin"],
    default: "visitor"
  },
  agencyName: String,
  agencyType: String,
  address: String,
  zip: String,
  country: String,
  favorites: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Service"
  }],
  isBlocked: {
    type: Boolean,
    default: false
  },
  blockedReason: String,
  blockedAt: Date,
  isVerified: {
    type: Boolean,
    default: false
  },
  otp: String,
  otpExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

export default mongoose.models.User || mongoose.model("User", UserSchema);
