const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const app = express();
app.use(express.json());

const PORT = 3000;
const SECRET = 'secretkey123';

// In-memory storage
const users = [];
const posts = [];
let postId = 1;

// Logger middleware
app.use((req, res, next) => {
  const log = `${new Date().toISOString()} ${req.method} ${req.url}\n`;
  fs.appendFileSync('logs.txt', log);
  next();
});

// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the blogging API (no database)');
});

// Register
app.post('/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 8);
  users.push({ id: users.length + 1, name, email, password: hashed, role: 'user' });
  res.send('User registered');
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).send('User not found');

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).send('Wrong password');

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET);
  res.json({ token });
});

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).send('No token');

  try {
    const token = header.split(' ')[1];
    const user = jwt.verify(token, SECRET);
    req.user = user;
    next();
  } catch {
    res.status(403).send('Invalid token');
  }
}

// Create Post
app.post('/posts', auth, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).send('Missing fields');
  const post = { id: postId++, title, content, authorId: req.user.id };
  posts.push(post);
  res.json(post);
});

// Get all posts
app.get('/posts', (req, res) => {
  res.json(posts);
});

// Get single post
app.get('/posts/:id', (req, res) => {
  const post = posts.find(p => p.id == req.params.id);
  if (!post) return res.status(404).send('Post not found');
  res.json(post);
});

// Update post
app.patch('/posts/:id', auth, (req, res) => {
  const post = posts.find(p => p.id == req.params.id);
  if (!post) return res.status(404).send('Post not found');

  if (post.authorId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).send('Not allowed');
  }

  if (req.body.title) post.title = req.body.title;
  if (req.body.content) post.content = req.body.content;

  res.json(post);
});

// Delete post
app.delete('/posts/:id', auth, (req, res) => {
  const index = posts.findIndex(p => p.id == req.params.id);
  if (index === -1) return res.status(404).send('Post not found');

  if (posts[index].authorId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).send('Not allowed');
  }

  posts.splice(index, 1);
  res.send('Deleted');
});

// View users (admin only)
app.get('/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admins only');
  res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role })));
});

// 404 handler
app.use((req, res) => {
  res.status(404).send('Not found');
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
