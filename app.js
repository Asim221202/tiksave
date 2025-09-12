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

// --- PROXY LİSTELERİ ---
const TIKTOK_PROXIES = [
    process.env.PROXY1_URL,
    process.env.PROXY2_URL,
    process.env.PROXY3_URL,
];

const INSTAGRAM_PROXIES = [
    process.env.INSTA_PROXY_URL
];

// Rastgele proxy seç
function getRandomProxy(proxies) {
    if (!proxies || proxies.length === 0) throw new Error("Proxy listesi boş.");
    const index = Math.floor(Math.random() * proxies.length);
    return proxies[index];
}

// --- TikTok Proxy İşlemcisi ---
async function fetchTikTokVideoFromProxy(url) {
    const tried = new Set();
    for (let i = 0; i < TIKTOK_PROXIES.length; i++) {
        const proxy = getRandomProxy(TIKTOK_PROXIES);
        if (tried.has(proxy)) continue;
        tried.add(proxy);
        try {
            const response = await axios.post(proxy, { url }, { timeout: 10000 });
            if (response.data && response.data.code === 0 && response.data.data) {
                return response.data.data;
            }
        } catch (err) {
            console.error(`TikTok Proxy hatası: ${proxy} - ${err.message}`);
        }
    }
    throw new Error("Tüm TikTok proxyleri başarısız oldu veya limit aşıldı");
}

// --- Instagram Proxy İşlemcisi ---
// Bu fonksiyonu, her istek geldiğinde taze bir URL almak için kullanıyoruz.
async function fetchInstagramMedia(url) {
    const tried = new Set();
    for (let i = 0; i < INSTAGRAM_PROXIES.length; i++) {
        const proxy = getRandomProxy(INSTAGRAM_PROXIES);
        if (tried.has(proxy)) continue;
        tried.add(proxy);
        try {
            const headers = { 'x-source': 'bot' };
            const response = await axios.post(proxy, { url }, { timeout: 30000, headers });
            if (response.data) return response.data;
        } catch (err) {
            console.error(`Instagram Proxy hatası: ${proxy} - ${err.message}`);
        }
    }
    throw new Error("Tüm Instagram proxyleri başarısız oldu veya limit aşıldı");
}

// EJS & Middleware
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
    await new Visit({ ip, userAgent: req.headers['user-agent'] }).save();
    const count = await Visit.countDocuments();
    res.render('index', { count, videoData: null });
});

// Statik sayfalar
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
    const manageableGuilds = user.guilds.filter(g => (g.permissions & 0x20) === 0x20 || (g.permissions & 0x8) === 0x8);
    res.render('dashboard', { user, guilds: manageableGuilds });
});

// --- API ROTLARI ---

// TikTok
app.post('/api/tiktok-process', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        const videoInfo = await fetchTikTokVideoFromProxy(url);
        let shortId;
        do { shortId = nanoid(); } while (await VideoLink.findOne({ shortId }));
        const newVideoLink = new VideoLink({ shortId, originalUrl: url, videoInfo });
        await newVideoLink.save();
        res.json({ success: true, shortId, videoInfo });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Tüm proxyler başarısız oldu veya limit aşıldı.' });
    }
});

// Instagram
app.post('/api/instagram-process', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        const mediaInfo = await fetchInstagramMedia(url);
        let shortId;
        do { shortId = nanoid(); } while (await VideoLink.findOne({ shortId }));
        const newVideoLink = new VideoLink({ shortId, originalUrl: url, videoInfo: mediaInfo });
        await newVideoLink.save();
        res.json({ success: true, shortId, mediaInfo });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Instagram proxy hatası veya limit aşıldı.' });
    }
});

// Twitter (FixupX)
app.post('/api/twitter-process', async (req, res) => {
    const { url: tweetUrl } = req.body;
    if (!tweetUrl) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        const regex = /(?:twitter\.com|x\.com)\/([a-zA-Z0-9_]+)\/status\/(\d+)/;
        const match = tweetUrl.match(regex);
        if (!match) return res.status(400).json({ success: false, message: 'Geçersiz Twitter/X URL' });
        const username = match[1];
        const statusId = match[2];
        const fixupUrl = `https://d.fixupx.com/${username}/status/${statusId}.mp4`;
        let shortId;
        do { shortId = nanoid(); } while (await VideoLink.findOne({ shortId }));
        const newVideoLink = new VideoLink({ shortId, originalUrl: tweetUrl, videoInfo: { media_url: fixupUrl } });
        await newVideoLink.save();
        res.json({ success: true, shortId, mediaInfo: { media_url: fixupUrl }, link: `${process.env.SITE_URL}/${shortId}` });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Twitter işleme hatası' });
    }
});

// Info butonu
app.get('/api/info/:shortId', async (req, res) => {
    try {
        const videoLink = await VideoLink.findOne({ shortId: req.params.shortId });
        if (!videoLink || !videoLink.videoInfo) return res.status(404).json({ success: false, message: 'Video bulunamadı' });
        res.json({ success: true, videoInfo: videoLink.videoInfo });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Sunucu hatası' });
    }
});

// Proxy download
app.get('/proxy-download', async (req, res) => {
    const { shortId, type, username, mediaIndex = 0 } = req.query;
    try {
        const videoLink = await VideoLink.findOne({ shortId });
        if (!videoLink || !videoLink.videoInfo) return res.status(404).send('Video bulunamadı');

        const mediaInfo = Array.isArray(videoLink.videoInfo.media) ? videoLink.videoInfo.media[mediaIndex] : videoLink.videoInfo;
        
        let videoUrl;
        if (type === 'video') {
            videoUrl = mediaInfo.media_url || mediaInfo.play || mediaInfo.hdplay;
            if (!videoUrl || !videoUrl.endsWith('.mp4')) {
                // If the primary URL isn't a video, check for an explicit video URL
                videoUrl = mediaInfo.hdplay || mediaInfo.play || mediaInfo.media_url;
            }
        } else {
            videoUrl = mediaInfo.media_url || mediaInfo.cover;
        }

        if (!videoUrl) return res.status(404).send('Video link bulunamadı');

        const extension = type === 'video' ? 'mp4' : 'jpg';
        const safeUsername = sanitize((username || 'unknown').replace(/[\s\W]+/g, '_')).substring(0, 30);
        const filename = `tikssave_${safeUsername}_${Date.now()}.${extension}`;

        const videoRes = await axios.get(videoUrl, { responseType: 'stream', headers: { 'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0' } });
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        videoRes.data.pipe(res);

    } catch (err) {
        res.status(500).send('Download error');
    }
});

// ShortId yönlendirme
app.get('/:shortId', async (req, res) => {
    try {
        const videoLink = await VideoLink.findOne({ shortId: req.params.shortId });
        if (!videoLink) return res.status(404).send('Video bulunamadı');

        let videoData = videoLink.videoInfo;

        const isInstagram = videoLink.originalUrl.includes('instagram.com') || videoLink.originalUrl.includes('instagr.am');
        const isTwitter = videoLink.originalUrl.includes('twitter.com') || videoLink.originalUrl.includes('x.com');
        const isTikTok = !isInstagram && !isTwitter;

        // Discord veya Telegram botu için yönlendirme
        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const isDiscordOrTelegram = userAgent.includes('discordbot') || userAgent.includes('telegrambot');

        // TikTok ve tekli Instagram gönderileri için direct yönlendirme
        if (isDiscordOrTelegram && isTikTok) {
            const redirectUrl = videoLink.videoInfo.hdplay || videoLink.videoInfo.play;
            if (redirectUrl) return res.redirect(307, redirectUrl);
        } else if (isDiscordOrTelegram && isInstagram && videoLink.videoInfo.media.length === 1) {
            const redirectUrl = videoLink.videoInfo.media[0].media_url;
            if (redirectUrl) return res.redirect(307, redirectUrl);
        }

        // Web tarayıcısı için
        res.render('index', { videoData: videoLink.videoInfo });

    } catch (err) {
        res.status(500).send('Sunucu hatası');
    }
});

app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
