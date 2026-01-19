import nodemailer from 'nodemailer';

export async function sendEmail(to, subject, text) {
  try {
    const smtpHost = process.env.SMTP_HOST;
    const smtpPort = process.env.SMTP_PORT;
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const fromEmail = process.env.FROM_EMAIL || 'noreply@test-dnvo4d93pnng5r86.mlsender.net'; // Temporary default using test domain

    console.log('Nodemailer Config:', {
      host: smtpHost,
      port: smtpPort,
      user: smtpUser ? 'Set' : 'Missing',
      pass: smtpPass ? 'Set' : 'Missing',
      fromEmail: fromEmail,
    });

    if (!smtpHost || !smtpPort || !smtpUser || !smtpPass) {
      throw new Error('SMTP configuration is incomplete. Check SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS environment variables.');
    }

    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort == 465, // true for 465, false for other ports
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });

    const mailOptions = {
      from: fromEmail,
      to: to,
      subject: subject,
      text: text,
    };

    const result = await transporter.sendMail(mailOptions);
    console.log('Email sent via Nodemailer:', result);
    return result;
  } catch (error) {
    console.error('Error sending email via Nodemailer:', error);
    throw error;
  }
}
