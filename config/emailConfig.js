const nodemailer = require("nodemailer");
require("dotenv").config();

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;

// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
  service:'zoho',
  host: 'smtp.zoho.com',
  port: 465, // Use port 465 for secure SSL connection
  secure: true, // true for 465, false for other ports
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASSWORD
  }
});

module.exports = transporter;
