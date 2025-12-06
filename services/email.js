import nodemailer from 'nodemailer';

// Email configuration from environment variables
const createTransporter = () => {
  // Resend SMTP (recommended for production)
  if (process.env.RESEND_API_KEY) {
    return nodemailer.createTransport({
      host: 'smtp.resend.com',
      port: 587,
      secure: false,
      auth: {
        user: 'resend',
        pass: process.env.RESEND_API_KEY
      }
    });
  }

  // For production, use SMTP from environment variables
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  // For development, use Gmail (you'll need to set up App Password)
  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
      }
    });
  }

  // Fallback: create test account (for development only)
  console.warn('⚠️ No email configuration found. Using test account. Emails will not be sent in production.');
  return null;
};

const transporter = createTransporter();

// Send verification code email
export async function sendVerificationEmail(email, verificationCode) {
  if (!transporter) {
    console.log(`[DEV] Verification code for ${email}: ${verificationCode}`);
    return { success: true, dev: true };
  }

  try {
    const fromEmail = process.env.EMAIL_FROM || process.env.RESEND_FROM || 'onboarding@resend.dev';
    
    const mailOptions = {
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
    };

    await transporter.sendMail(mailOptions);
    return { success: true };
  } catch (error) {
    console.error('Error sending verification email:', error);
    throw new Error('Failed to send verification email');
  }
}

// Send password reset email
export async function sendPasswordResetEmail(email, resetToken) {
  if (!transporter) {
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    console.log(`[DEV] Password reset link for ${email}: ${resetUrl}`);
    return { success: true, dev: true, resetUrl };
  }

  try {
    const frontendUrl = process.env.FRONTEND_URL || 'https://goymessage.netlify.app';
    const resetUrl = `${frontendUrl}/reset-password?token=${resetToken}`;

    const fromEmail = process.env.EMAIL_FROM || process.env.RESEND_FROM || 'onboarding@resend.dev';
    
    const mailOptions = {
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
    };

    await transporter.sendMail(mailOptions);
    return { success: true, resetUrl };
  } catch (error) {
    console.error('Error sending password reset email:', error);
    throw new Error('Failed to send password reset email');
  }
}

