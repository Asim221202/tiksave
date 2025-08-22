require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const https = require('https');
const sanitize = require('sanitize-filename');
const session = require('express-session');
const passport = require('passport');
const { Strategy: DiscordStrategy } = require('passport-discord');
const Visit = require('./models/Visit');
const Download = require('./models/Download');
const VideoLink = require('./models/VideoLink');
const { customAlphabet } = require('nanoid');
const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 7);
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

// Discord OAuth2
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;

// Proxy listesi (sırasıyla veya rastgele seçilecek)
const PROXIES = [
  process.env.PROXY1_URL,
  process.env.PROXY2_URL
];

// Helper: shortId üret
function generateShortId() {
  return nanoid();
}

// TikWM Proxy üzerinden video al (retry + fallback)
async function fetchVideoFromProxy(url) {
  for (const proxyUrl of PROXIES) {
    for (let attempt = 0; attempt < 2; attempt++) { // 2 deneme
      try {
        const res = await axios.post(proxyUrl, { url }, { timeout: 10000 });
        if (res.data && res.data.code === 0 && res.data.data) {
          return res.data.data;
        } else if (res.data?.msg?.toLowerCase().includes('limit')) {
          console.warn(`Proxy limit: ${proxyUrl} - ${res.data.msg}`);
          break; // diğer proxyye geç
        } else {
          console.warn(`Proxy başarısız: ${proxyUrl} - ${res.data?.msg || 'Unknown error'}`);
        }
      } catch (err) {
        console.warn(`Proxy hatası: ${proxyUrl} - ${err.message}`);
        await new Promise(r => setTimeout(r, 1000)); // 1 saniye bekle
      }
    }
  }
  throw new Error('Tüm proxyler başarısız oldu veya limit aşıldı');
}

// EJS ve static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session & Passport
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Discord OAuth2
passport.use(new DiscordStrategy({
  clientID: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  callbackURL: CALLBACK_URL,
  scope: ['identify', 'guilds']
}, (accessToken, refreshToken, profile, done) => done(null, profile)));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// --- ROTLAR ---

// Ana sayfa
app.get('/', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const visit = new Visit({ ip, userAgent: req.headers['user-agent'] });
  await visit.save();
  const count = await Visit.countDocuments();
  res.render('index', { count, videoData: null });
});

app.get('/ads.txt', (req, res) => res.redirect('https://srv.adstxtmanager.com/19390/tikssave.xyz'));
app.get('/discord', (req, res) => res.render('discord'));
app.get('/privacy', (req, res) => res.render('privacy'));
app.get('/terms', (req, res) => res.render('terms'));
app.get('/rights', (req, res) => res.render('rights'));

// Discord Dashboard
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/dashboard' }),
  (req, res) => res.redirect('/dashboard')
);
app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.render('dashboard', { user: null, guilds: null });
  const user = req.user;
  const manageableGuilds = user.guilds.filter(guild => (guild.permissions & 0x20) === 0x20 || (guild.permissions & 0x8) === 0x8);
  res.render('dashboard', { user, guilds: manageableGuilds });
});

// --- API ROTLARI ---

app.post('/api/tiktok-process', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ success: false, message: 'URL yok' });

  try {
    const videoInfo = await fetchVideoFromProxy(url);

    // ShortId üret ve kaydet
    let shortId, exists;
    do {
      shortId = generateShortId();
      exists = await VideoLink.findOne({ shortId });
    } while (exists);

    const newVideoLink = new VideoLink({ shortId, originalUrl: url, videoInfo });
    await newVideoLink.save();

    console.log(`Yeni video kaydedildi: ${shortId}`);
    res.json({ success: true, shortId, videoInfo });

  } catch (err) {
    console.error('API işleme hatası:', err.message);
    res.status(500).json({ success: false, message: 'Tüm proxyler başarısız oldu veya limit aşıldı.' });
  }
});

// ShortId ile info çek
app.get('/api/info/:shortId', async (req, res) => {
  try {
    const videoLink = await VideoLink.findOne({ shortId: req.params.shortId });
    if (!videoLink || !videoLink.videoInfo) return res.status(404).json({ success: false, message: 'Video bulunamadı veya bilgiler eksik.' });
    res.json({ success: true, videoInfo: videoLink.videoInfo });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Sunucu hatası.' });
  }
});

// Proxy download
// Proxy download
app.get('/proxy-download', async (req, res) => {
  const { url, username, type, shortId } = req.query;
  let videoUrl = url;

  if (shortId) {
    try {
      const videoLink = await VideoLink.findOne({ shortId });
      if (!videoLink || !videoLink.videoInfo) return res.status(404).send('Video bulunamadı');
      videoUrl = videoLink.videoInfo.hdplay || videoLink.videoInfo.play;
    } catch (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }
  }

  if (!videoUrl) return res.status(400).send('Video link yok');

  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  await new Download({ url: videoUrl, ip }).save();

  const extension = (type === 'music') ? 'mp3' : 'mp4';
  const safeUsername = sanitize((username || 'unknown').replace(/[\s\W]+/g, '_')).substring(0, 30);
  const filename = `tikssave_${safeUsername}_${Date.now()}.${extension}`;

  try {
    const videoRes = await axios.get(videoUrl, {
      responseType: 'stream',
      maxRedirects: 5,
      headers: {
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0'
      },
      timeout: 15000
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    videoRes.data.pipe(res);

  } catch (err) {
    console.error('Download error:', err.message);
    res.status(500).send('Download error');
  }
});

// ShortId ile redirect
app.get('/:shortId', async (req, res) => {
  const videoLink = await VideoLink.findOne({ shortId: req.params.shortId });
  if (!videoLink) return res.status(404).send('Video bulunamadı');

  let videoData = videoLink.videoInfo;
  if (!videoData) {
    try {
      const response = await axios.post('https://www.tikwm.com/api/', { url: videoLink.originalUrl });
      const data = response.data;
      if (!data || data.code !== 0) return res.status(404).send('Video bilgisi alınamadı');
      videoData = data.data;
      videoLink.videoInfo = videoData;
      await videoLink.save();
    } catch (err) {
      console.error(err);
      return res.status(500).send('Sunucu hatası');
    }
  }

  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const isDiscordOrTelegram = userAgent.includes('discordbot') || userAgent.includes('telegrambot');
  const acceptsVideo = (req.headers['accept'] || '').includes('video/mp4');
  if (isDiscordOrTelegram || acceptsVideo) {
    if (videoData.hdplay || videoData.play) return res.redirect(307, videoData.hdplay || videoData.play);
  }

  res.render('index', { videoData });
});

app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
