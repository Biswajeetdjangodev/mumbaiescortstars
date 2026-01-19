'use client'
import { useState } from 'react';

export default function OTPVerification({ email, type, onSuccess, onCancel }) {
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});

  const handleVerify = async (e) => {
    e.preventDefault();

    if (!otp) {
      setErrors({ otp: 'OTP is required' });
      return;
    }

    if (type === 'reset' && !newPassword) {
      setErrors({ newPassword: 'New password is required' });
      return;
    }

    if (type === 'reset' && newPassword.length < 6) {
      setErrors({ newPassword: 'Password must be at least 6 characters' });
      return;
    }

    setLoading(true);
    setErrors({});

    try {
      const response = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          otp,
          type,
          newPassword: type === 'reset' ? newPassword : undefined
        }),
      });

      const data = await response.json();

      if (response.ok) {
        alert(data.message);
        onSuccess && onSuccess(data);
      } else {
        alert(data.error || 'Verification failed');
      }
    } catch (error) {
      console.error('Verification error:', error);
      alert('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleResendOTP = async () => {
    setLoading(true);

    try {
      const response = await fetch('/api/auth/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, type }),
      });

      const data = await response.json();

      if (response.ok) {
        alert('OTP sent successfully');
        console.log('New OTP:', data.otp); // For testing only
      } else {
        alert(data.error || 'Failed to send OTP');
      }
    } catch (error) {
      console.error('Resend OTP error:', error);
      alert('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-purple-50 p-8 flex items-center justify-center">
      <form onSubmit={handleVerify} className="bg-linear-to-br from-purple-900 via-purple-800 to-purple-900 bg-opacity-90 backdrop-blur-md p-8 rounded-xl text-white space-y-6 w-full max-w-md shadow-2xl">
        <h2 className="text-3xl font-extrabold text-center mb-8 tracking-wide">
          {type === 'verification' ? 'Verify Account' : 'Reset Password'}
        </h2>

        <p className="text-center text-purple-200 mb-6">
          {type === 'verification'
            ? `Enter the 6-digit code sent to ${email}`
            : `Enter the 6-digit code sent to ${email} to reset your password`
          }
        </p>

        {/* OTP Input */}
        <div>
          <input
            type="text"
            value={otp}
            onChange={(e) => {
              const value = e.target.value.replace(/\D/g, '').slice(0, 6);
              setOtp(value);
              if (errors.otp) setErrors({ ...errors, otp: '' });
            }}
            placeholder="Enter 6-digit OTP"
            className={`w-full p-3 rounded-md focus:outline-none focus:ring-2 placeholder:text-white text-white focus:ring-white border-white border-2 text-center text-2xl font-mono tracking-widest ${
              errors.otp ? 'border-2 border-red-500' : ''
            }`}
            maxLength={6}
          />
          {errors.otp && <p className="text-red-400 text-sm mt-1">{errors.otp}</p>}
        </div>

        {/* New Password Input (only for reset) */}
        {type === 'reset' && (
          <div>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => {
                setNewPassword(e.target.value);
                if (errors.newPassword) setErrors({ ...errors, newPassword: '' });
              }}
              placeholder="New Password *"
              className={`w-full p-3 placeholder:text-white text-white rounded-md focus:outline-none focus:ring-2 focus:ring-white border-2 border-white ${
                errors.newPassword ? 'border-2 border-red-500' : ''
              }`}
            />
            {errors.newPassword && <p className="text-red-400 text-sm mt-1">{errors.newPassword}</p>}
          </div>
        )}



        {/* Submit Button */}
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-linear-to-r from-purple-700 to-purple-500 hover:from-purple-800 hover:to-purple-600 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-3 rounded-md font-semibold transition-all duration-200 shadow-lg"
        >
          {loading ? 'Verifying...' : (type === 'verification' ? 'Verify Account' : 'Reset Password')}
        </button>

        {/* Resend OTP */}
        <div className="text-center">
          <button
            type="button"
            onClick={handleResendOTP}
            disabled={loading}
            className="text-purple-200 hover:text-white underline disabled:opacity-50"
          >
            Didn&apos;t receive code? Resend OTP
          </button>
        </div>

        {/* Cancel Button */}
        {onCancel && (
          <div className="text-center">
            <button
              type="button"
              onClick={onCancel}
              className="text-purple-200 hover:text-white underline"
            >
              Cancel
            </button>
          </div>
        )}
      </form>
    </div>
  );
}
