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
const Redis = require('ioredis'); // YENİ: Redis kütüphanesi

const app = express();
const port = process.env.PORT || 3000;

// Discord OAuth2
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;

// --- REDIS BAĞLANTISI ---
const redis = new Redis(process.env.REDIS_URL || 'redis://127.0.0.1:6379');
redis.on('connect', () => console.log('Redis connected'));
redis.on('error', (err) => console.error('Redis connection error:', err));


// --- PROXY LİSTELERİ ---
const TIKTOK_PROXIES = [
    process.env.PROXY1_URL,
    process.env.PROXY2_URL,
    process.env.PROXY3_URL,
    process.env.PROXY4_URL,
];

// Python API'nin URL'si - Instagram için artık kullanılmıyor, ama TikTok için kalacak.
const PYTHON_API_URL = process.env.PYTHON_API_URL;

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

// TikTok - GÜNCELLENMİŞ ROTA
app.post('/api/tiktok-process', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        const videoInfo = await fetchTikTokVideoFromProxy(url);
        let shortId;
        do { shortId = nanoid(); } while (await VideoLink.findOne({ shortId }));
        
        // TikTok verisi doğrudan videoInfo alanına kaydediliyor (media dizisi yerine)
        const newVideoLink = new VideoLink({ shortId, originalUrl: url, videoInfo });
        await newVideoLink.save();

        // YENİ: Veriyi Redis'e kaydet
        await redis.setex(`tiktok:${shortId}`, 3600 * 24 * 7, JSON.stringify(videoInfo)); // 7 günlük TTL

        // Client-side'a TikTok'a özgü veriyi gönder
        res.json({ 
            success: true, 
            shortId,
            desc: videoInfo.desc,
            cover: videoInfo.cover,
            play: videoInfo.play,
            hdplay: videoInfo.hdplay,
            music: videoInfo.music,
            username: videoInfo.author?.unique_id || 'tiktok'
        });
        
    } catch (err) {
        res.status(500).json({ success: false, message: 'Tüm proxyler başarısız oldu veya limit aşıldı.' });
    }
});

// Instagram
app.post('/api/instagram-process', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, message: 'URL yok' });
    try {
        let shortId;
        do { shortId = nanoid(); } while (await VideoLink.findOne({ shortId }));
        
        // Bu rotada video bilgisi çekilmiyor, client'ın kendi JS'i kullanılıyor gibi görünüyor.
        // Download'un çalışması için bu rotanın tam olarak ne döndürmesi gerektiğini kontrol edin.
        // Eğer client side'da `/api/get-media` kullanılıyorsa, bu rota atlanıyor olabilir.
        const newVideoLink = new VideoLink({ shortId, originalUrl: url, videoInfo: { type: 'instagram' } });
        await newVideoLink.save();
        
        res.json({ success: true, shortId, message: "Instagram verisi henüz bu rotadan çekilmiyor, lütfen client-side script'i kontrol edin." });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Instagram işlemi başarısız oldu.' });
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

// GÜNCELLENMİŞ PROXY DOWNLOAD ROTA
app.get('/proxy-download', async (req, res) => {
    // shortId: TikTok için kullanılır (DB'den URL çeker)
    // url: Instagram/Twitter gibi platformlar için client-side'dan direkt gönderilen URL
    const { shortId, type, username, url: directUrl, mediaIndex = 0 } = req.query; 

    try {
        let videoInfo;
        let videoUrl;
        let originalUrl = directUrl; // Default olarak directUrl'ı kullan

        if (shortId) {
            // Case 1: TikTok (shortId ile)
            const videoLink = await VideoLink.findOne({ shortId });
            if (!videoLink) return res.status(404).send('Video verisi bulunamadı (shortId).');

            videoInfo = videoLink.videoInfo;
            originalUrl = videoLink.originalUrl;
            
            // İstenen türe göre doğru URL'yi seç
            if (type === 'hdplay') {
                videoUrl = videoInfo.hdplay;
            } else if (type === 'play') {
                videoUrl = videoInfo.play;
            } else if (type === 'music') {
                videoUrl = videoInfo.music;
            } else if (type === 'video' && (videoInfo.hdplay || videoInfo.play)) {
                // Yedek durum, sadece 'video' tipi gelirse
                videoUrl = videoInfo.hdplay || videoInfo.play;
            }
            
        } else if (directUrl) {
            // Case 2: Diğer platformlar (direkt URL ile)
            videoUrl = directUrl;
            
        } else {
            return res.status(400).send('İndirme bilgisi eksik (shortId veya url).');
        }

        if (!videoUrl) return res.status(404).send('İstenen tür için indirme linki bulunamadı.');

        // Dosya uzantısını ve MIME tipini belirle
        let extension = 'mp4';
        let contentType = 'video/mp4';
        
        if (type === 'music') {
            extension = 'mp3';
            contentType = 'audio/mpeg';
        } else if (type === 'image') {
            extension = 'jpg';
            contentType = 'image/jpeg';
        } else if (videoUrl.includes('.jpg') || videoUrl.includes('.jpeg')) {
            extension = 'jpg';
            contentType = 'image/jpeg';
        } else if (videoUrl.includes('.gif')) {
            extension = 'gif';
            contentType = 'image/gif';
        } else if (videoUrl.includes('.mp3')) {
            extension = 'mp3';
            contentType = 'audio/mpeg';
        }


        // --- Dosya Adlandırma & Streaming ---
        const safeUsername = sanitize((username || 'tikssave').replace(/[\s\W]+/g, '_')).substring(0, 30);
        const filename = `tikssave_${safeUsername}_${Date.now()}.${extension}`;

        const videoRes = await axios.get(videoUrl, { 
            responseType: 'stream', 
            // Bazı medya sunucularının User-Agent ve Referer kontrolü yapması nedeniyle sahte başlıklar gönderilir
            headers: { 
                'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
                'Referer': originalUrl || 'https://www.tiktok.com/'
            },
            timeout: 15000 // 15 saniye timeout
        });
        
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', contentType);
        // İsteğe bağlı: İçerik uzunluğunu ileterek indirme ilerlemesini sağlar
        if (videoRes.headers['content-length']) {
            res.setHeader('Content-Length', videoRes.headers['content-length']);
        }
        
        videoRes.data.pipe(res);

    } catch (err) {
        console.error('Proxy download error:', err.message);
        res.status(500).send('Download error: Failed to stream the file.');
    }
});


// ShortId yönlendirme - GÜNCELLENMİŞ ROTA
app.get('/:shortId', async (req, res) => {
    const { shortId } = req.params;
    
    if (shortId.length < 7 || shortId.includes('http')) {
        return res.status(404).send('Video bulunamadı');
    }
    
    try {
        const videoLink = await VideoLink.findOne({ shortId: req.params.shortId });
        if (!videoLink) {
            console.error('Veritabanında video bulunamadı, shortId:', shortId);
            return res.status(404).send('Video bulunamadı');
        }

        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const isDiscordOrTelegram = userAgent.includes('discordbot') || userAgent.includes('telegrambot');
        const isInstagram = videoLink.originalUrl.includes('instagram.com') || videoLink.originalUrl.includes('instagr.am');
        const isTikTok = videoLink.originalUrl.includes('tiktok.com');

        let videoData = videoLink.videoInfo;

        // YENİ: Önce Redis'ten veriyi çekmeyi dene
        if (isTikTok) {
            const cachedVideoInfo = await redis.get(`tiktok:${shortId}`);
            if (cachedVideoInfo) {
                videoData = JSON.parse(cachedVideoInfo);
                console.log(`Veri Redis'ten çekildi: ${shortId}`);
            } else {
                console.log(`Redis'te veri bulunamadı, API'den çekiliyor: ${shortId}`);
                // Eski kodun API'den veri çekme ve veritabanını güncelleme mantığı
                const freshVideoInfo = await fetchTikTokVideoFromProxy(videoLink.originalUrl);
                videoData = freshVideoInfo;
                videoLink.videoInfo = freshVideoInfo;
                await videoLink.save();
                // YENİ: API'den çekilen veriyi Redis'e kaydet
                await redis.setex(`tiktok:${shortId}`, 3600 * 24 * 7, JSON.stringify(freshVideoInfo));
            }
        }
        
        // Instagram linki Discord botundan geldiyse direkt vxinstagram'a yönlendir
        if (isDiscordOrTelegram && isInstagram) {
            const vxUrl = videoLink.originalUrl
                .replace('instagram.com/p/', 'vxinstagram.com/p/')
                .replace('instagram.com/reel/', 'vxinstagram.com/reel/');
            return res.redirect(307, vxUrl);
        } else if (isDiscordOrTelegram && !isInstagram) {
            // TikTok ve Twitter için redirect mantığı
            const isTwitter = videoLink.originalUrl.includes('twitter.com') || videoLink.originalUrl.includes('x.com');
            let mediaUrl = null;
            if (isTikTok && videoData.play) {
                mediaUrl = videoData.play;
            } else if (isTwitter && videoData.media_url) {
                mediaUrl = videoData.media_url;
            }
            if (mediaUrl) {
                return res.redirect(307, mediaUrl);
            }
        }
        
        // Normal kullanıcılar için orijinal linke yönlendirme
        res.redirect(videoLink.originalUrl);

    } catch (err) {
        console.error('ShortId route error:', err);
        res.status(500).send('Sunucu hatası');
    }
});

app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
