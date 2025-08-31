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
const Download = require('nanoid');
const VideoLink = require('./models/VideoLink');
const { customAlphabet } = require('nanoid');
const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 7);
const axios = require('axios');
const url = require('url');

const app = express();
const port = process.env.PORT || 3000;

// Discord OAuth2
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;

// --- PROXY LİSTELERİ ---
// Her bir API için ayrı proxy listesi
const TIKTOK_PROXIES = [
    process.env.PROXY1_URL,
    process.env.PROXY2_URL,
    process.env.PROXY3_URL,
];

// Senin kendi oluşturduğun Instagram proxy'si
const INSTAGRAM_PROXIES = [
    process.env.INSTA_PROXY_URL
];

// Rastgele proxy seç
function getRandomProxy(proxies) {
    if (!proxies || proxies.length === 0) {
        throw new Error("Proxy listesi boş.");
    }
    const index = Math.floor(Math.random() * proxies.length);
    return proxies[index];
}

// --- TİKTOK İÇİN PROXY İŞLEMCİSİ ---
// Bu fonksiyon sadece TikTok URL'lerini işler.
async function fetchTikTokVideoFromProxy(url) {
    const tried = new Set();
    for (let i = 0; i < TIKTOK_PROXIES.length; i++) {
        const proxy = getRandomProxy(TIKTOK_PROXIES);
        if (tried.has(proxy)) continue;
        tried.add(proxy);

        try {
            console.log(`🎯 TikTok Proxy deneniyor: ${proxy}`);
            const response = await axios.post(proxy, { url }, { timeout: 10000 });
            if (response.data && response.data.code === 0 && response.data.data) {
                console.log(`✅ TikTok Proxy başarılı: ${proxy}`);
                return response.data.data;
            } else {
                console.warn(`⚠️ TikTok Proxy başarısız: ${proxy} - ${response.data?.msg || 'Unknown error'}`);
            }
        } catch (error) {
            console.error(`❌ TikTok Proxy hatası: ${proxy} - ${error.message}`);
        }
    }
    throw new Error("Tüm TikTok proxyleri başarısız oldu veya limit aşıldı");
}

// --- INSTAGRAM İÇİN PROXY İŞLEMCİSİ ---
// Bu fonksiyon sadece Instagram URL'lerini işler.
async function fetchInstagramMedia(url) {
    const tried = new Set();
    for (let i = 0; i < INSTAGRAM_PROXIES.length; i++) {
        const proxy = getRandomProxy(INSTAGRAM_PROXIES);
        if (tried.has(proxy)) continue;
        tried.add(proxy);

        try {
            console.log(`🎯 Instagram Proxy deneniyor: ${proxy}`);
            const headers = {
                'x-source': 'bot' // Python API'nizin beklediği başlık eklendi
            };
            
            const response = await axios.post(proxy, { url }, {
                timeout: 30000, // Instagram API için zaman aşımı süresi 30 saniyeye çıkarıldı
                headers: headers
            });
            
            // Python API'nizin doğrudan medya bilgisini döndürdüğünü varsayarak
            if (response.data) {
                console.log(`✅ Instagram Proxy başarılı: ${proxy}`);
                return response.data; // Python API'nin döndürdüğü doğrudan medya bilgisi
            } else {
                console.warn(`⚠️ Instagram Proxy başarısız: ${proxy} - ${response.data?.message || 'Unknown error'}`);
            }
        } catch (error) {
            console.error(`❌ Instagram Proxy hatası: ${proxy} - ${error.message}`);
            // AxiosError detaylarını yazdır
            if (axios.isAxiosError(error)) {
                console.error('Axios Hata Detayları:', error.response ? error.response.data : error.message);
            }
        }
    }
    throw new Error("Tüm Instagram proxyleri başarısız oldu veya limit aşıldı");
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

// TikTok işleme rotası (mevcut)
app.post('/api/tiktok-process', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        const videoInfo = await fetchTikTokVideoFromProxy(url);
        let shortId, exists;
        do {
            shortId = nanoid();
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

// Instagram Discord bot rotası
// Bu rota sadece Instagram URL'lerini işler. TikTok ile karışmaz.
app.post('/api/instagram-process', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        const mediaInfo = await fetchInstagramMedia(url);
        
        let shortId, exists;
        do {
            shortId = nanoid();
            exists = await VideoLink.findOne({ shortId });
        } while (exists);

        const newVideoLink = new VideoLink({ shortId, originalUrl: url, videoInfo: mediaInfo });
        await newVideoLink.save();
        console.log(`Yeni Instagram medyası kaydedildi: ${shortId}`);
        res.json({ success: true, shortId, mediaInfo });
    } catch (err) {
        console.error('Instagram API işleme hatası:', err.message);
        res.status(500).json({ success: false, message: 'Instagram proxy hatası veya limit aşıldı.' });
    }
});

// Yeni Instagram web rotası
// Bu rota da sadece web arayüzü için Instagram URL'lerini işler.
app.post('/api/instagram-download', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        const mediaInfo = await fetchInstagramMedia(url);
        // Doğrudan döndürülen veriyi kullanın. Python API'si zaten 'success' anahtarı döndürmüyor.
        res.json({ success: true, data: mediaInfo });
    } catch (err) {
        console.error('Web Instagram API işleme hatası:', err.message);
        res.status(500).json({ success: false, message: err.message || 'Beklenmedik bir hata oluştu.' });
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
app.get('/proxy-download', async (req, res) => {
    const { url, username, type, shortId } = req.query;
    let videoUrl = url;

    if (shortId) {
        try {
            const videoLink = await VideoLink.findOne({ shortId });
            if (!videoLink || !videoLink.videoInfo) return res.status(404).send('Video bulunamadı');
            
            const isInstagram = videoLink.originalUrl.includes('instagram.com') || videoLink.originalUrl.includes('instagr.am');
            
            if (isInstagram) {
                videoUrl = videoLink.videoInfo.media_url;
            } else {
                videoUrl = videoLink.videoInfo.hdplay || videoLink.videoInfo.play;
            }
        } catch (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
    }

    if (!videoUrl) return res.status(400).send('Video link yok');

    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    await new Download({ url: videoUrl, ip }).save();

    const extension = (type === 'music') ? 'mp3' : videoUrl.endsWith('.mp4') ? 'mp4' : 'jpg';
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
    try {
        const videoLink = await VideoLink.findOne({ shortId: req.params.shortId });
        if (!videoLink) return res.status(404).send('Video bulunamadı');

        let videoData;

        const isInstagram = videoLink.originalUrl.includes('instagram.com') || videoLink.originalUrl.includes('instagr.am');

        try {
            if (isInstagram) {
                const freshData = await fetchInstagramMedia(videoLink.originalUrl);
                videoData = freshData;
                videoLink.videoInfo = freshData;
            } else {
                const freshData = await fetchTikTokVideoFromProxy(videoLink.originalUrl);
                videoData = freshData;
                videoLink.videoInfo = freshData;
            }
            await videoLink.save();
            console.log(`♻️ Video bilgisi güncellendi: ${videoLink.shortId}`);
        } catch (err) {
            console.error('Yeniden fetch hatası:', err.message);
            videoData = videoLink.videoInfo;
        }

        if (!videoData) {
            return res.status(404).send('Video bilgisi alınamadı');
        }

        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const isDiscordOrTelegram = userAgent.includes('discordbot') || userAgent.includes('telegrambot');
        const acceptsVideo = (req.headers['accept'] || '').includes('video/mp4');

        if (isDiscordOrTelegram || acceptsVideo) {
            const redirectUrl = isInstagram ? videoData.media_url : videoData.hdplay || videoData.play;
            if (redirectUrl) {
                return res.redirect(307, redirectUrl);
            }
        }

        res.render('index', { videoData });

    } catch (err) {
        console.error(err);
        res.status(500).send('Sunucu hatası');
    }
});

app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
