import { Resend } from 'resend';

// Initialize Resend client
let resend = null;

if (process.env.RESEND_API_KEY) {
  resend = new Resend(process.env.RESEND_API_KEY);
  console.log('✅ Resend API client initialized');
  console.log(`📧 RESEND_FROM: ${process.env.RESEND_FROM || 'onboarding@resend.dev'}`);
} else {
  console.error('❌ RESEND_API_KEY not found in environment variables!');
  console.error('❌ Emails will NOT be sent. Please set RESEND_API_KEY in Railway.');
}

// Send verification code email
export async function sendVerificationEmail(email, verificationCode) {
  console.log(`📧 Attempting to send verification email to: ${email}`);
  console.log(`🔑 Verification code: ${verificationCode}`);
  
  if (!resend) {
    console.log(`⚠️ [DEV MODE] No Resend client configured. Verification code for ${email}: ${verificationCode}`);
    console.log(`⚠️ Please set RESEND_API_KEY in Railway environment variables`);
    return { success: true, dev: true };
  }

  try {
    const fromEmail = process.env.EMAIL_FROM || process.env.RESEND_FROM || 'onboarding@resend.dev';
    console.log(`📤 Sending email from: ${fromEmail}`);
    console.log(`📥 Sending email to: ${email}`);
    
    const { data, error } = await resend.emails.send({
      from: fromEmail,
      to: email,
      subject: 'goyMessage - Email Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Thank you for registering with goyMessage!</p>
          <p>Your verification code is:</p>
          <div style="background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;">
            <h1 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;">${verificationCode}</h1>
          </div>
          <p>This code will expire in 10 minutes.</p>
          <p>If you didn't register for goyMessage, please ignore this email.</p>
        </div>
      `
    });

    if (error) {
      console.error('❌ Resend API error:', error);
      console.error(`⚠️ VERIFICATION CODE FOR ${email}: ${verificationCode}`);
      throw new Error(`Failed to send verification email: ${error.message}`);
    }

    console.log(`✅ Verification email sent successfully to ${email}`);
    console.log(`📧 Email ID: ${data?.id || 'N/A'}`);
    return { success: true };
  } catch (error) {
    console.error('❌ Error sending verification email:', error);
    console.error('❌ Error details:', {
      message: error.message,
      name: error.name,
      stack: error.stack
    });
    
    // Always log the verification code so user can still verify
    console.error(`⚠️ VERIFICATION CODE FOR ${email}: ${verificationCode}`);
    console.error(`⚠️ User can still verify using this code, even though email failed`);
    
    throw new Error(`Failed to send verification email: ${error.message}`);
  }
}

// Send password reset email
export async function sendPasswordResetEmail(email, resetToken) {
  if (!resend) {
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    console.log(`[DEV] Password reset link for ${email}: ${resetUrl}`);
    return { success: true, dev: true, resetUrl };
  }

  try {
    const frontendUrl = process.env.FRONTEND_URL || 'https://goymessage.netlify.app';
    const resetUrl = `${frontendUrl}/reset-password?token=${resetToken}`;
    const fromEmail = process.env.EMAIL_FROM || process.env.RESEND_FROM || 'onboarding@resend.dev';

    console.log(`📧 Attempting to send password reset email to: ${email}`);
    console.log(`🔗 Reset URL: ${resetUrl}`);

    const { data, error } = await resend.emails.send({
      from: fromEmail,
      to: email,
      subject: 'goyMessage - Reset Your Password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>You requested to reset your password for goyMessage.</p>
          <p>Click the button below to reset your password:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
          </div>
          <p>Or copy and paste this link into your browser:</p>
          <p style="color: #666; word-break: break-all;">${resetUrl}</p>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request a password reset, please ignore this email.</p>
        </div>
      `
    });

    if (error) {
      console.error('❌ Resend API error:', error);
      throw new Error(`Failed to send password reset email: ${error.message}`);
    }

    console.log(`✅ Password reset email sent successfully to ${email}`);
    console.log(`📧 Email ID: ${data?.id || 'N/A'}`);
    return { success: true, resetUrl };
  } catch (error) {
    console.error('❌ Error sending password reset email:', error);
    console.error('❌ Error details:', {
      message: error.message,
      name: error.name,
      stack: error.stack
    });
    throw new Error(`Failed to send password reset email: ${error.message}`);
  }
}
