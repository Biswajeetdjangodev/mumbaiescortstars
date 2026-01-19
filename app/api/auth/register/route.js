import { connectDB } from "@/lib/db";
import User from "@/lib/models/User";
import bcrypt from "bcryptjs";
import { sendEmail } from "@/lib/email";

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export async function POST(req) {
  try {
    await connectDB();
    const { email, password, role, phone } = await req.json();

    if (!email || !password || !role) {
      return new Response(JSON.stringify({ error: "Email, password, and role are required" }), { status: 400 });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return new Response(JSON.stringify({ error: "User already exists" }), { status: 400 });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      role,
      phone,
      isVerified: false, // Will be verified via OTP
    });

    // Generate OTP for verification
    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    user.otp = otp;
    user.otpExpires = otpExpires;

    await user.save();

    // Send OTP via email
    try {
      await sendEmail(
        email,
        'Your OTP Code',
        `Your OTP code is: ${otp}. It expires in 10 minutes.`
      );
    } catch (emailError) {
      console.error('Error sending email:', emailError);
      return new Response(JSON.stringify({ error: "Failed to send OTP email" }), { status: 500 });
    }

    return new Response(JSON.stringify({
      message: "Registration successful! Please verify your account with the OTP sent to your email.",
      expiresIn: "10 minutes"
    }), { status: 200 });

  } catch (error) {
    console.error("Registration error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
  }
}
