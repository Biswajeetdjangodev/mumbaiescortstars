import { connectDB } from "@/lib/db";
import User from "@/lib/models/User";
import bcrypt from "bcryptjs";

export async function POST(req) {
  try {
    await connectDB();
    const { email, otp, type, newPassword } = await req.json(); // type: 'verification' or 'reset'

    if (!email || !otp || !type) {
      return new Response(JSON.stringify({ error: "Email, OTP, and type are required" }), { status: 400 });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
    }

    // Check if OTP is valid and not expired
    if (user.otp !== otp || user.otpExpires < new Date()) {
      return new Response(JSON.stringify({ error: "Invalid or expired OTP" }), { status: 400 });
    }

    if (type === 'verification') {
      // Verify account
      user.isVerified = true;
      user.otp = undefined;
      user.otpExpires = undefined;
      await user.save();

      return new Response(JSON.stringify({
        message: "Account verified successfully",
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified
        }
      }), { status: 200 });

    } else if (type === 'reset') {
      // Reset password
      if (!newPassword) {
        return new Response(JSON.stringify({ error: "New password is required" }), { status: 400 });
      }

      if (newPassword.length < 6) {
        return new Response(JSON.stringify({ error: "Password must be at least 6 characters" }), { status: 400 });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.otp = undefined;
      user.otpExpires = undefined;
      await user.save();

      return new Response(JSON.stringify({
        message: "Password reset successfully"
      }), { status: 200 });

    } else {
      return new Response(JSON.stringify({ error: "Invalid type" }), { status: 400 });
    }

  } catch (error) {
    console.error("Verify OTP error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
  }
}
