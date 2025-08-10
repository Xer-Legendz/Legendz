# Legendz
// server.js — Legendz Fun Club (single-file backend + frontend)
// Run:
// 1. npm init -y
// 2. npm install express socket.io mongoose cors dotenv jsonwebtoken bcryptjs
// 3. create .env as shown below
// 4. node server.js
// MONGO_URI=mongodb://127.0.0.1:27017/legendz_fun_club
JWT_SECRET=some_long_secure_random_string
PORT=5000
// Then open http://localhost:5000

require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Basic middleware
app.use(cors());
app.use(express.json());

// ---------- MongoDB ----------
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/legendz_fun_club';
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ---------- Schemas ----------
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const MessageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);

// ---------- Helpers ----------
const JWT_SECRET = process.env.JWT_SECRET || 'replace_me_with_a_secret';

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- API ----------

// register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'User already exists' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// list users (simple)
app.get('/api/users', authMiddleware, async (req, res) => {
  const users = await User.find({}, 'name email');
  res.json(users);
});

// get messages between current user and other user id
app.get('/api/messages/:otherId', authMiddleware, async (req, res) => {
  try {
    const me = req.userId;
    const other = req.params.otherId;
    const msgs = await Message.find({ $or: [{ from: me, to: other }, { from: other, to: me }] })
      .sort('createdAt')
      .populate('from', 'name email')
      .populate('to', 'name email');
    res.json(msgs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// serve simple health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- Socket.IO (auth via token) ----------
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Auth error'));
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.id;
    // optional: fetch user
    const user = await User.findById(socket.userId);
    if (!user) return next(new Error('Auth error'));
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Auth error'));
  }
});

io.on('connection', (socket) => {
  console.log('🔌 socket connected', socket.user.email);
  // join personal room
  socket.join(socket.userId.toString());

  // receive private message
  // payload: { to: userIdString, text: 'hello' }
  socket.on('private_message', async (payload) => {
    try {
      const { to, text } = payload;
      if (!to || !text) return;
      const msg = await Message.create({ from: socket.userId, to, text });
      const populated = await msg.populate('from', 'name email').populate('to', 'name email');

      // emit to sender and recipient
      io.to(socket.userId.toString()).emit('message', populated);
      io.to(to.toString()).emit('message', populated);
    } catch (err) {
      console.error('socket message error', err);
    }
  });

  socket.on('disconnect', () => {
    console.log('❌ socket disconnected', socket.user.email);
  });
});

// ---------- FRONTEND: single-file SPA ----------
// We'll serve one HTML page at / that contains the frontend app (React from CDN).
// The frontend uses axios and socket.io client (CDN) and connects to the same server.

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Legendz Fun Club</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <!-- Tailwind via CDN for quick styling (dev only) -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      html,body,#root{height:100%}
    </style>
  </head>
  <body class="bg-gray-100">
    <div id="root"></div>

    <!-- React + ReactDOM UMD -->
    <script src="https://unpkg.com/react@18/umd/react.development.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
    <!-- Axios -->
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <!-- Socket.IO client -->
    <script src="/socket.io/socket.io.js"></script>

    <script>
      const e = React.createElement;
      const { useState, useEffect, useRef } = React;

      const API_BASE = '';

      // helper to set axios auth header
      function setAuth(token) {
        if (token) axios.defaults.headers.common['Authorization'] = 'Bearer ' + token;
        else delete axios.defaults.headers.common['Authorization'];
      }

      function App() {
        const [token, setToken] = useState(localStorage.getItem('lfc_token'));
        const [user, setUser] = useState(JSON.parse(localStorage.getItem('lfc_user') || 'null'));

        useEffect(() => {
          if (token) setAuth(token);
        }, [token]);

        if (!token) {
          return e(Auth, { onLogin: (t, u) => {
            localStorage.setItem('lfc_token', t);
            localStorage.setItem('lfc_user', JSON.stringify(u));
            setToken(t); setUser(u); setAuth(t);
          }});
        }

        return e(LegendzFunClub, { token, user, onLogout: () => {
          localStorage.removeItem('lfc_token'); localStorage.removeItem('lfc_user');
          setToken(null); setUser(null); setAuth(null);
        }});
      }

      function Auth({ onLogin }) {
        const [mode, setMode] = useState('login');
        const [email, setEmail] = useState('');
        const [name, setName] = useState('');
        const [password, setPassword] = useState('');

        async function submit() {
          try {
            if (mode === 'login') {
              const r = await axios.post('/api/login', { email, password });
              onLogin(r.data.token, r.data.user);
            } else {
              const r = await axios.post('/api/register', { name, email, password });
              onLogin(r.data.token, r.data.user);
            }
          } catch (err) {
            alert(err.response?.data?.error || 'Auth failed');
          }
        }

        return e('div', { className: 'h-screen flex items-center justify-center' },
          e('div', { className: 'bg-white p-6 rounded shadow w-full max-w-md' },
            e('h2', { className: 'text-xl font-semibold mb-4' }, 'Legendz Fun Club — ' + mode),
            mode === 'register' && e('input', { placeholder: 'Name', value: name, onChange: e=>setName(e.target.value), className: 'w-full p-2 border rounded mb-2' }),
            e('input', { placeholder: 'Email', value: email, onChange: e=>setEmail(e.target.value), className: 'w-full p-2 border rounded mb-2' }),
            e('input', { type: 'password', placeholder: 'Password', value: password, onChange: e=>setPassword(e.target.value), className: 'w-full p-2 border rounded mb-4' }),
            e('button', { className: 'w-full bg-green-600 text-white py-2 rounded', onClick: submit }, mode === 'login' ? 'Login' : 'Register'),
            e('div', { className: 'text-center mt-3 text-sm' },
              e('button', { className: 'text-green-600', onClick: () => setMode(mode === 'login' ? 'register' : 'login') },
                mode === 'login' ? 'Create account' : 'Already have an account?'
              )
            )
          )
        );
      }

      function LegendzFunClub({ token, user, onLogout }) {
        const [users, setUsers] = useState([]);
        const [activeId, setActiveId] = useState(null);
        const [messages, setMessages] = useState({});
        const [input, setInput] = useState('');
        const socketRef = useRef(null);
        const endRef = useRef(null);

        useEffect(() => {
          setAuth(token);
          // fetch users
          axios.get('/api/users').then(r => {
            // server returns {_id, name, email}
            setUsers(r.data.map(u => ({ id: u._id, name: u.name || u.email, email: u.email })));
          }).catch(console.error);

          // connect socket
          const socket = io({ auth: { token } });
          socketRef.current = socket;

          socket.on('connect_error', (err) => console.error('Socket error', err));
          socket.on('message', (m) => {
            // populate local messages: m.from, m.to are objects
            const otherId = (m.from._id === user.id) ? m.to._id : m.from._id;
            setMessages(prev => {
              const arr = prev[otherId] ? [...prev[otherId]] : [];
              arr.push(m);
              return { ...prev, [otherId]: arr };
            });
          });

          return () => socket.disconnect();
        }, []);

        useEffect(() => { scrollToBottom(); }, [messages, activeId]);

        function scrollToBottom() { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }

        async function openChat(otherId) {
          setActiveId(otherId);
          if (!messages[otherId]) {
            const r = await axios.get('/api/messages/' + otherId);
            setMessages(prev => ({ ...prev, [otherId]: r.data }));
          }
        }

        function sendMessage() {
          if (!input.trim() || !activeId) return;
          socketRef.current.emit('private_message', { to: activeId, text: input });
          setInput('');
        }

        return e('div', { className: 'h-screen w-screen flex text-sm' },
          // sidebar
          e('aside', { className: 'w-96 border-r bg-white flex flex-col' },
            e('header', { className: 'px-4 py-3 flex items-center gap-3 border-b' },
              e('div', { className: 'flex-1' },
                e('h1', { className: 'text-lg font-semibold' }, 'Legendz Fun Club'),
                e('p', { className: 'text-xs text-gray-500' }, user.name || user.email)
              ),
              e('button', { className: 'px-3 py-1 rounded-md border text-xs', onClick: onLogout }, 'Logout')
            ),
            e('div', { className: 'p-3' },
              e('input', { placeholder: 'Search', className: 'w-full rounded-md border p-2 text-sm' })
            ),
            e('div', { className: 'flex-1 overflow-auto' },
              users.map(u =>
                e('button', { key: u.id, onClick: () => openChat(u.id), className: 'w-full text-left flex gap-3 items-center px-3 py-2 hover:bg-gray-50' + (u.id === activeId ? ' bg-gray-50' : '') },
                  e('div', { className: 'w-12 h-12 rounded-full bg-indigo-400 flex items-center justify-center text-white font-semibold' }, (u.name||'U').slice(0,2)),
                  e('div', { className: 'flex-1' },
                    e('div', { className: 'font-medium' }, u.name),
                    e('div', { className: 'text-xs text-gray-500 truncate' }, (messages[u.id]||[]).slice(-1)[0]?.text || 'Say hi to start the chat')
                  )
                )
              )
            )
          ),
          // chat area
          e('main', { className: 'flex-1 flex flex-col' },
            activeId ? e(React.Fragment, null,
              e('div', { className: 'flex items-center gap-4 px-6 py-3 border-b bg-white' },
                e('div', { className: 'font-semibold' }, users.find(x=>x.id===activeId)?.name || 'Chat')
              ),
              e('div', { className: 'flex-1 overflow-auto p-6 bg-[url(\"data:image/svg+xml;utf8,<svg xmlns=\\'http://www.w3.org/2000/svg\\' width=\\'200\\' height=\\'200\\'><text x=\\'0\\' y=\\'15\\' font-size=\\'12\\' fill=\\'%23e5e7eb\\'>Legendz Fun Club background</text></svg>)\"]' },
                e('div', { className: 'max-w-3xl mx-auto' },
                  (messages[activeId]||[]).map((m, i) =>
                    e('div', { key: i, className: 'mb-3 flex ' + ((m.from._id === user.id) ? 'justify-end' : 'justify-start') },
                      e('div', { className: ((m.from._id === user.id) ? 'bg-green-600 text-white' : 'bg-white text-black border') + ' p-3 rounded-lg shadow-sm max-w-[70%]' },
                        e('div', null, m.text),
                        e('div', { className: 'text-[10px] text-gray-200 mt-1 text-right' }, new Date(m.createdAt).toLocaleTimeString())
                      )
                    )
                  ),
                  e('div', { ref: endRef })
                )
              ),
              e('div', { className: 'p-4 border-t bg-white' },
                e('div', { className: 'max-w-3xl mx-auto flex items-center gap-3' },
                  e('input', { value: input, onChange: e=>setInput(e.target.value), onKeyDown: e=>{ if(e.key==='Enter') sendMessage() }, placeholder: 'Type a message', className: 'w-full rounded-full border px-4 py-2 focus:outline-none' }),
                  e('button', { onClick: sendMessage, className: 'px-4 py-2 rounded-full bg-green-600 text-white font-semibold' }, 'Send')
                )
              )
            ) : e('div', { className: 'flex-1 flex items-center justify-center' }, 'Select a conversation to start chatting')
          )
        );
      }

      ReactDOM.createRoot(document.getElementById('root')).render(e(App));
    </script>
  </body>
</html>
`);
});

// ---------- start ----------
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log('🚀 Legendz Fun Club running on port', PORT);
});
