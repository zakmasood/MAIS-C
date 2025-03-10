const OpenAI = require('openai');
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(express.static('public')); // Serve static files

// Initialize SQLite database
const db = new sqlite3.Database('database.db', (err) => {
  if (err) console.error('Could not connect to SQLite', err);
  else console.log('Connected to SQLite database');
});

// Create tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    messages TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// JWT secret (in production, use environment variables)
const secret = crypto.randomBytes(32).toString('hex');
const JWT_SECRET = secret;

// Initialize OpenAI instance
const openai = new OpenAI({
  apiKey: 'API_KEY_HERE'
});

// JWT middleware to verify token
function authenticate(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Serve the homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// API: Chat processing (TTS and ChatGPT)
app.post('/api/ask', async (req, res) => {
  try {
    const prompt = req.body.prompt;
    if (!prompt) throw new Error("No prompt provided");

    // Generate the text response using ChatGPT
    const chatCompletion = await openai.chat.completions.create({
      model: "gpt-4o-mini-2024-07-18",
      messages: [
        { role: "system", content: "You are a helpful assistant, you can empathize with the user, and feel emotions. Also, have a little flair! Be like everyone's favorite therapist." },
        { role: "user", content: prompt }
      ],
      max_tokens: 500,
    });
    const choices = chatCompletion.data?.choices || chatCompletion.choices;
    if (!choices || choices.length === 0) throw new Error("No completion choices returned");
    const textResponse = choices[0].message.content.trim();

    // Generate the TTS audio response
    const ttsResponse = await openai.audio.speech.create({
      model: "tts-1",
      voice: "alloy",
      input: textResponse
    });
    const audioBuffer = Buffer.from(await ttsResponse.arrayBuffer());
    const audioBase64 = audioBuffer.toString('base64');

    res.json({
      text: textResponse,
      audio: `data:audio/mpeg;base64,${audioBase64}`
    });
  } catch (error) {
    console.error("Error processing request:", error);
    res.status(500).json({ error: error.message });
  }
});

// Registration
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password], function(err) {
    if (err) res.json({ success: false, message: err.message });
    else {
      const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET);
      res.json({ success: true, token });
    }
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) res.json({ success: false, message: err.message });
    else if (!row) res.json({ success: false, message: 'User not found' });
    else if (row.password !== password) res.json({ success: false, message: 'Incorrect password' });
    else {
      const token = jwt.sign({ id: row.id, username: row.username }, JWT_SECRET);
      res.json({ success: true, token });
    }
  });
});

// Create a new chat conversation
app.post('/api/chats/new', authenticate, (req, res) => {
  const title = req.body.title || 'New Conversation';
  const messages = JSON.stringify([]);
  db.run("INSERT INTO chats (user_id, title, messages) VALUES (?, ?, ?)", [req.user.id, title, messages], function(err) {
    if (err) return res.status(500).json({ message: err.message });
    console.log("Chat saved with id:", this.lastID);
    db.get("SELECT * FROM chats WHERE id = ?", [this.lastID], (err, row) => {
      if (err) res.status(500).json({ message: err.message });
      else res.json(row);
    });
  });
});

// Get all chats for the logged-in user
app.get('/api/chats', authenticate, (req, res) => {
  db.all("SELECT * FROM chats WHERE user_id = ? ORDER BY datetime(createdAt) DESC", [req.user.id], (err, rows) => {
    if (err) res.status(500).json({ message: err.message });
    else res.json(rows);
  });
});

// Append a message to a specific chat
app.post('/api/chats/:chatId/message', authenticate, (req, res) => {
  const chatId = req.params.chatId;
  const { sender, content } = req.body;
  db.get("SELECT * FROM chats WHERE id = ? AND user_id = ?", [chatId, req.user.id], (err, row) => {
    if (err) return res.status(500).json({ message: err.message });
    if (!row) return res.status(404).json({ message: 'Chat not found' });
    
    let messages = [];
    try {
      messages = JSON.parse(row.messages);
    } catch (e) {
      messages = [];
    }
    messages.push({ sender, content });
    const newMessages = JSON.stringify(messages);
    db.run("UPDATE chats SET messages = ? WHERE id = ?", [newMessages, chatId], function(err) {
      if (err) return res.status(500).json({ message: err.message });
      db.get("SELECT * FROM chats WHERE id = ?", [chatId], (err, updatedRow) => {
        if (err) res.status(500).json({ message: err.message });
        else res.json(updatedRow);
      });
    });
  });
});

// A simple test endpoint to simulate saving a chat from a button
app.post('/api/saveChatTest', (req, res) => {
  const title = req.body.title || 'Test Chat';
  const messages = JSON.stringify([{ sender: 'user', content: 'Test message' }]);
  // Using dummy user_id (1) for testing.
  db.run("INSERT INTO chats (user_id, title, messages) VALUES (?, ?, ?)", [1, title, messages], function(err) {
    if (err) return res.status(500).json({ message: err.message });
    console.log("Test chat saved with id:", this.lastID);
    res.json({ message: 'Test chat saved', id: this.lastID });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
