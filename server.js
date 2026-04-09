const express = require('express');
const axios = require('axios');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const CLIENT_ID = process.env.CLIENT_ID;
const SCOPES = 'openid profile email offline_access https://graph.microsoft.com/Mail.Read';
const JWT_SECRET = 'supersecretformvp';

let pendingDeviceFlow = null;
let connectedInboxes = [];

// Hardcoded admin
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'password';

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Wrong username or password' });
});

const checkAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Bad token' });
  }
};

// Start Microsoft device flow - using /consumers for personal accounts
app.post('/api/init-device-flow', async (req, res) => {
  if (!CLIENT_ID) {
    return res.status(500).json({ error: 'CLIENT_ID is missing! Check Render Environment.' });
  }
  try {
    const response = await axios.post('https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode',
      new URLSearchParams({ client_id: CLIENT_ID, scope: SCOPES }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    pendingDeviceFlow = response.data;
    startPolling();
    res.json({ user_code: pendingDeviceFlow.user_code, verification_uri: pendingDeviceFlow.verification_uri });
  } catch (err) {
    console.error('Microsoft error:', err.response?.data || err.message);
    const errorMsg = err.response?.data?.error_description || err.response?.data?.error || 'Cannot start Microsoft';
    res.status(500).json({ error: errorMsg });
  }
});

app.get('/api/get-device-code', (req, res) => {
  if (!pendingDeviceFlow) return res.status(404).json({ error: 'No code' });
  res.json({ user_code: pendingDeviceFlow.user_code, verification_uri: pendingDeviceFlow.verification_uri });
});

function startPolling() {
  const poll = async () => {
    if (!pendingDeviceFlow) return;
    try {
      const res = await axios.post('https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
        new URLSearchParams({
          client_id: CLIENT_ID,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: pendingDeviceFlow.device_code
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      const tokenData = res.data;
      const newInbox = { id: Date.now(), email: 'Connected User', displayName: 'Microsoft Inbox', accessToken: tokenData.access_token };
      connectedInboxes.push(newInbox);
      pendingDeviceFlow = null;
    } catch (e) {
      if (e.response?.data?.error === 'authorization_pending') {
        setTimeout(poll, 5000);
      } else {
        pendingDeviceFlow = null;
      }
    }
  };
  poll();
}

// Dashboard APIs
app.get('/api/connected-inboxes', checkAdmin, (req, res) => res.json(connectedInboxes));

app.get('/api/inbox-emails/:id', checkAdmin, async (req, res) => {
  const inbox = connectedInboxes.find(i => i.id.toString() === req.params.id);
  if (!inbox) return res.status(404).json({ error: 'No inbox' });
  try {
    const response = await axios.get('https://graph.microsoft.com/v1.0/me/messages?$top=10&$orderby=receivedDateTime DESC', {
      headers: { Authorization: `Bearer ${inbox.accessToken}` }
    });
    res.json(response.data.value);
  } catch (err) {
    res.status(500).json({ error: 'Cannot get emails' });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('App is ready!'));
