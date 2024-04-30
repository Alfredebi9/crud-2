const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const path = require("path");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

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
  username: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

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

// Routes
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
    res.redirect("/login");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error registering user");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
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
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
