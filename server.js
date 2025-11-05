// server.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const DB_PATH = path.join(__dirname, "db.json");
const JWT_SECRET = "demo_secret_change_in_prod"; // for demo only
const TOKEN_EXP = "7d";

// Helpers to read/write DB
function readDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    return { users: [], posts: [], comments: [] };
  }
}
function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// Simple ID generators (timestamp + random)
function id() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// Auth middleware
function authMiddleware(req, res, next) {
  const h = req.headers["authorization"];
  if (!h) return res.status(401).json({ message: "No token" });
  const token = h.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ---------------- AUTH ROUTES ---------------- */

// Register
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) return res.status(400).json({ message: "Missing fields" });

  const db = readDB();
  if (db.users.find(u => u.email === email || u.username === username)) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: id(),
    username,
    email,
    password: hashed,
    bio: "",
    avatarUrl: "",
    createdAt: new Date().toISOString()
  };

  db.users.push(newUser);
  writeDB(db);

  const token = jwt.sign({ id: newUser.id }, JWT_SECRET, { expiresIn: TOKEN_EXP });
  // don’t send password back
  const safe = { ...newUser }; delete safe.password;
  res.json({ token, user: safe });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { emailOrUsername, password } = req.body || {};
  if (!emailOrUsername || !password) return res.status(400).json({ message: "Missing fields" });

  const db = readDB();
  const user = db.users.find(u => u.email === emailOrUsername || u.username === emailOrUsername);
  if (!user) return res.status(400).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: TOKEN_EXP });
  const safe = { ...user }; delete safe.password;
  res.json({ token, user: safe });
});

/* ---------------- USERS ---------------- */

// Get public profile
app.get("/api/users/:id", (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  const safe = { ...user }; delete safe.password;
  res.json(safe);
});

// Update own profile
app.put("/api/users", authMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ message: "User not found" });
  const { username, bio, avatarUrl } = req.body || {};
  if (username) user.username = username;
  if (bio !== undefined) user.bio = bio;
  if (avatarUrl !== undefined) user.avatarUrl = avatarUrl;
  writeDB(db);
  const safe = { ...user }; delete safe.password;
  res.json(safe);
});

/* ---------------- POSTS ---------------- */

// Create post
app.post("/api/posts", authMiddleware, (req, res) => {
  const { title, content } = req.body || {};
  if (!title || !content) return res.status(400).json({ message: "Missing fields" });

  const db = readDB();
  const newPost = {
    id: id(),
    authorId: req.userId,
    title,
    content,
    likes: [],     // array of userIds
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  db.posts.unshift(newPost); // newest first
  writeDB(db);
  res.status(201).json(newPost);
});

// Read all posts (with author info)
app.get("/api/posts", (req, res) => {
  const db = readDB();
  // populate author small info
  const posts = db.posts.map(p => {
    const author = db.users.find(u => u.id === p.authorId) || { username: "unknown", avatarUrl: "" };
    return { ...p, author: { id: author.id, username: author.username, avatarUrl: author.avatarUrl } };
  });
  res.json(posts);
});

// Read single post with comments
app.get("/api/posts/:id", (req, res) => {
  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: "Post not found" });
  const author = db.users.find(u => u.id === post.authorId) || { username: "unknown" };
  const comments = db.comments.filter(c => c.postId === post.id)
    .map(c => {
      const a = db.users.find(u => u.id === c.authorId) || { username: "unknown" };
      return { ...c, author: { id: a.id, username: a.username } };
    });
  res.json({ ...post, author: { id: author.id, username: author.username }, comments });
});

// Update post (only author)
app.put("/api/posts/:id", authMiddleware, (req, res) => {
  const { title, content } = req.body || {};
  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: "Post not found" });
  if (post.authorId !== req.userId) return res.status(403).json({ message: "Not authorized" });
  if (title) post.title = title;
  if (content) post.content = content;
  post.updatedAt = new Date().toISOString();
  writeDB(db);
  res.json(post);
});

// Delete post (only author)
app.delete("/api/posts/:id", authMiddleware, (req, res) => {
  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: "Post not found" });
  if (post.authorId !== req.userId) return res.status(403).json({ message: "Not authorized" });
  db.posts = db.posts.filter(p => p.id !== post.id);
  // also delete comments belonging to the post
  db.comments = db.comments.filter(c => c.postId !== post.id);
  writeDB(db);
  res.json({ message: "Deleted" });
});

// Like/unlike post
app.post("/api/posts/:id/like", authMiddleware, (req, res) => {
  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: "Post not found" });
  const idx = post.likes.indexOf(req.userId);
  if (idx === -1) post.likes.push(req.userId);
  else post.likes.splice(idx, 1);
  writeDB(db);
  res.json({ likesCount: post.likes.length, liked: idx === -1 });
});

/* ---------------- COMMENTS ---------------- */

// Add comment
app.post("/api/posts/:id/comments", authMiddleware, (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ message: "Comment is empty" });

  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: "Post not found" });

  const newComment = {
    id: id(),
    postId: post.id,
    authorId: req.userId,
    text,
    createdAt: new Date().toISOString()
  };
  db.comments.push(newComment);
  writeDB(db);
  const author = db.users.find(u => u.id === req.userId) || { username: "unknown" };
  res.status(201).json({ ...newComment, author: { id: author.id, username: author.username } });
});

// Delete comment (only author)
app.delete("/api/comments/:id", authMiddleware, (req, res) => {
  const db = readDB();
  const comment = db.comments.find(c => c.id === req.params.id);
  if (!comment) return res.status(404).json({ message: "Comment not found" });
  if (comment.authorId !== req.userId) return res.status(403).json({ message: "Not authorized" });
  db.comments = db.comments.filter(c => c.id !== comment.id);
  writeDB(db);
  res.json({ message: "Comment deleted" });
});

/* ---------------- Server ---------------- */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("Server running on port " + PORT));
