import nodemailer from 'nodemailer';

// Email configuration from environment variables
const createTransporter = () => {
  // Resend SMTP (recommended for production)
  if (process.env.RESEND_API_KEY) {
    console.log('✅ Resend API key found, creating email transporter...');
    console.log(`📧 RESEND_API_KEY: ${process.env.RESEND_API_KEY.substring(0, 15)}...`);
    console.log(`📧 RESEND_FROM: ${process.env.RESEND_FROM || 'onboarding@resend.dev'}`);
    
    const transporter = nodemailer.createTransport({
      host: 'smtp.resend.com',
      port: 587,
      secure: false,
      auth: {
        user: 'resend',
        pass: process.env.RESEND_API_KEY
      }
    });
    
    // Verify connection on startup
    transporter.verify((error, success) => {
      if (error) {
        console.error('❌ Email transporter verification failed:', error);
        console.error('❌ Check RESEND_API_KEY in Railway environment variables');
      } else {
        console.log('✅ Email transporter verified and ready to send emails');
      }
    });
    
    return transporter;
  } else {
    console.error('❌ RESEND_API_KEY not found in environment variables!');
    console.error('❌ Emails will NOT be sent. Please set RESEND_API_KEY in Railway.');
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
  console.log(`📧 Attempting to send verification email to: ${email}`);
  console.log(`🔑 Verification code: ${verificationCode}`);
  
  if (!transporter) {
    console.log(`⚠️ [DEV MODE] No email transporter configured. Verification code for ${email}: ${verificationCode}`);
    console.log(`⚠️ Please set RESEND_API_KEY in Railway environment variables`);
    return { success: true, dev: true };
  }

  try {
    const fromEmail = process.env.EMAIL_FROM || process.env.RESEND_FROM || 'onboarding@resend.dev';
    console.log(`📤 Sending email from: ${fromEmail}`);
    console.log(`📥 Sending email to: ${email}`);
    
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

    // Add timeout to email sending (10 seconds)
    const emailPromise = transporter.sendMail(mailOptions);
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Email timeout')), 10000)
    );

    const result = await Promise.race([emailPromise, timeoutPromise]);
    console.log(`✅ Verification email sent successfully to ${email}`);
    console.log(`📧 Email result:`, JSON.stringify(result, null, 2));
    console.log(`📧 Message ID: ${result.messageId || 'N/A'}`);
    console.log(`📧 Response: ${result.response || 'N/A'}`);
    console.log(`📧 Accepted: ${result.accepted || 'N/A'}`);
    console.log(`📧 Rejected: ${result.rejected || 'N/A'}`);
    return { success: true };
  } catch (error) {
    console.error('❌ Error sending verification email:', error);
    console.error('❌ Error details:', {
      message: error.message,
      code: error.code,
      response: error.response,
      responseCode: error.responseCode,
      command: error.command
    });
    
    // Always log the verification code so user can still verify
    console.error(`⚠️ VERIFICATION CODE FOR ${email}: ${verificationCode}`);
    console.error(`⚠️ User can still verify using this code, even though email failed`);
    
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

