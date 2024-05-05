const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const path = require("path");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const EMAIL_USER = process.env.EMAIL_USER;


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


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Connect to MongoDB Atlas
mongoose.connect(MONGODB_URI);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => console.log("Connected to MongoDB Atlas"));

// Define user schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);


// Routes

// Registration
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send("Email already exists");
    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create a new user instance
    const newUser = new User({ username, email, password: hashedPassword });
    // Save the user to the database
    await newUser.save();
    // send verification email
    const mailOptions = {
      from: EMAIL_USER,
      to: email,
      subject: `Email Confirmation - CRUD-2` ,
      html: '<h1>Welcome to CRUD</h1> Click the link below to verify your email <br> https://crud-2-beta.vercel.app/verify/' + newUser._id
    };
    // Function to send email using nodemailer with promises
    transporter.sendMail(mailOptions, (error, info)=>{
      if (error) {
        console.error(error);
        console.log(error);
        return res.status(500).send("Error sending verification email");
      } else {
        console.log("Verification email sent: " + info.response);
        console.log(info.accepted);
        console.log(info.rejected);
        res.redirect("/login");
      }
     })
    console.log(`Email sent: ${process.env.EMAIL_USER}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error registering user");
  }
});

// Email verification
app.get("/verify/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    // Find the user by userId
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send("User not found");
    }
    // Set the user's verified status to true
    user.verified = true;
    await user.save();
    
    // After setting verification to true, redirect to the login page
    res.redirect("/login");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error verifying email");
  }
});

// login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      if (!user.verified) {
        return res.status(401).send("Email not verified. Please verify your email before logging in.");
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (isPasswordValid) {
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        // Send the token back to the client
        res.cookie("token", token, { httpOnly: true });
        res.cookie("username", user.username);
        res.redirect("/");
      } else {
        res.status(401).send("Invalid email or password");
      }
    } else {
      res.status(401).send("Invalid email or password");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error logging in");
  }
});

// Serve registration page
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

// Serve login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Add a new route for logging out
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.clearCookie("username");
  res.redirect("/login");
});



// Forgot Password
app.get("/forgot-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "forgot-password.html"));
});

// Handle forgotten password form submission
app.post("/forgot-password", async (req, res) => {
  try {
      const { email } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
          return res.status(404).send("User not found");
      }
      
      // Generate a password reset token and send it to the user's email
      const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
      const resetLink = `https://crud-2-beta.vercel.app/reset-password?token=${resetToken}`;
      
      const mailOptions = {
          from: EMAIL_USER,
          to: email,
          subject: "Password Reset Request",
          html: `Click the link below to reset your password: <a href="${resetLink}">${resetLink}</a>`
      };
      
      transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
              console.error(error);
              return res.status(500).send("Error sending password reset email");
          } else {
              console.log("Password reset email sent: " + info.response);
              res.send("Password reset instructions sent to your email");
          }
      });
  } catch (error) {
      console.error(error);
      res.status(500).send("Error processing password reset request");
  }
});

// Serve forgot password page
app.get("/reset-password", (req, res) => {
  const token = req.query.token;
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
          return res.status(401).send("Invalid or expired token. Please try again.");
      }
      res.sendFile(path.join(__dirname, "public", "reset-password.html"));
  });
});

// Handle password reset form submission
app.post("/reset-password", async (req, res) => {
  try {
      const { token, newPassword } = req.body;
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      if (!user) {
          return res.status(404).send("User not found");
      }
      
      // Update user's password with the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();
      
      res.send("Password reset successful. You can now login with your new password.");
  } catch (error) {
      console.error(error);
      res.status(500).send("Error resetting password");
  }
});


// Serve home page or login page based on authentication status
app.get("/", (req, res) => {
  const token = req.cookies.token;
  const username = req.cookies.username;
  if (token && username) {
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        // Token is invalid or expired, clear cookies and redirect to login page
        res.clearCookie("token");
        res.clearCookie("username");
        res.redirect("/login");
      } else {
        // Token is valid, find the user and serve the home page with the username
        res.sendFile(path.join(__dirname, "public", "index.html"));
      }
    });
  } else {
    // No token or username found, serve login page
    res.redirect("/login");
  }
});



// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.status(401).send("Unauthorized");
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Forbidden");
    req.user = user;
    next();
  });
};

app.get("/protected", authenticateToken, (req, res) => {
  res.send("You are authorized");
});

// Start the server
// module.exports = app
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
