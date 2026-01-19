import { connectDB } from "@/lib/db";
import User from "@/lib/models/User";
import { sendEmail } from "@/lib/email";

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export async function POST(req) {
  try {
    await connectDB();
    const { email, type } = await req.json(); // type: 'verification' or 'reset'

    if (!email || !type) {
      return new Response(JSON.stringify({ error: "Email and type are required" }), { status: 400 });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
    }

    if (type === 'verification' && user.isVerified) {
      return new Response(JSON.stringify({ error: "Account already verified" }), { status: 400 });
    }

    // Generate OTP
    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Save OTP to user
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
      message: "OTP sent successfully",
      expiresIn: "10 minutes"
    }), { status: 200 });

  } catch (error) {
    console.error("Send OTP error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
  }
}
