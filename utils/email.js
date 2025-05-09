import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables

export const sendEmail = async (to, subject, text) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER, // Replace with your email
      pass: process.env.EMAIL_PASS,   // Replace with your email password
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER, // Replace with your email
    to,
    subject,
    text,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error('Error sending email:', err);
    throw new Error('Error sending email');
  }
};
