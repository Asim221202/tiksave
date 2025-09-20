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

// Python API'nin URL'si
const PYTHON_API_URL = process.env.PYTHON_API_URL; // Buraya Render'da host ettiğin API URL'ini ekle

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

// --- Instagram API İşlemcisi ---
async function fetchInstagramMedia(shortcode) {
    try {
        const response = await axios.get(`${PYTHON_API_URL}?shortcode=${shortcode}`, { timeout: 30000 });
        
        // HATA GİDERME: Gelen yanıtı kontrol et ve logla
        if (!response.data) {
             console.error("Python API'den boş yanıt geldi.");
             throw new Error("Python API'den boş yanıt geldi.");
        }
        
        console.log("Python API'den gelen ham veri:", JSON.stringify(response.data, null, 2));

        // HATA GİDERME: Gelen veri yapısını doğrula
        if (response.data.video_url || (response.data.image_urls && response.data.image_urls.length > 0)) {
            return response.data;
        }

        // Eğer beklenen veri yapısı yoksa, detaylı hata fırlat
        console.error("API'den beklenen veri yapısı dönmedi. Gelen veri:", response.data);
        throw new Error("Python API'den başarıyla veri alınamadı veya format hatalı.");

    } catch (err) {
        console.error(`Python API hatası: ${err.message}`);
        if (err.response && err.response.data && err.response.data.error) {
            console.error(`API'den gelen hata: ${err.response.data.error}`);
        }
        throw err;
    }
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
        // Shortcode'u güvenilir bir şekilde URL'den çıkar
        const shortcodeMatch = url.match(/(?:(?:instagram\.com|instagr\.am)\/(?:p|reel|tv)\/)?([a-zA-Z0-9_-]+)/);
        const shortcode = shortcodeMatch ? shortcodeMatch[1] : null;

        if (!shortcode) {
            return res.status(400).json({ success: false, message: 'Geçersiz Instagram URL veya shortcode bulunamadı.' });
        }
        
        // Yeni fetch fonksiyonumuzu kullanarak Python API'den veri al
        const mediaInfo = await fetchInstagramMedia(shortcode);

        let shortId;
        do { shortId = nanoid(); } while (await VideoLink.findOne({ shortId }));
        
        // Python API'nin döndürdüğü veri yapısını kaydet
        const newVideoLink = new VideoLink({ shortId, originalUrl: url, videoInfo: mediaInfo });
        await newVideoLink.save();
        
        // Yanıtta mediaInfo'yu geri döndür
        res.json({ success: true, shortId, mediaInfo });
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
    const { shortId } = req.params;
    
    // HATA GİDERME: Kısa kodun geçerli olup olmadığını kontrol et
    // Eğer shortId 7 karakterden kısa veya https/http içeriyorsa, geçersiz say
    const isValidShortId = shortId.length >= 7 && !shortId.includes('http');
    if (!isValidShortId) {
        console.error('Geçersiz kısa kod isteği tespit edildi:', shortId);
        return res.status(404).send('Video bulunamadı');
    }
    
    try {
        const videoLink = await VideoLink.findOne({ shortId: req.params.shortId });
        if (!videoLink) return res.status(404).send('Video bulunamadı');

        const noembedParam = req.query.noembed === 'true';

        let videoData = videoLink.videoInfo;
        const isInstagram = videoLink.originalUrl.includes('instagram.com') || videoLink.originalUrl.includes('instagr.am');
        const isTwitter = videoLink.originalUrl.includes('twitter.com') || videoLink.originalUrl.includes('x.com');
        const isTikTok = !isInstagram && !isTwitter;
        
        // Bu loglamaları ekledim. Hangi URL'in ne olarak algılandığını görmek için loglara bak.
        console.log(`--- Yönlendirme Kontrolü ---`);
        console.log(`Original URL: ${videoLink.originalUrl}`);
        console.log(`isInstagram: ${isInstagram}`);
        console.log(`isTikTok: ${isTikTok}`);

        try {
            if (isInstagram) {
                console.log('--- Instagram URL\'i olarak işleniyor...');
                // Shortcode'u yeniden çıkar
                const shortcodeMatch = videoLink.originalUrl.match(/(?:(?:instagram\.com|instagr\.am)\/(?:p|reel|tv)\/)?([a-zA-Z0-9_-]+)/);
                const shortcode = shortcodeMatch ? shortcodeMatch[1] : null;

                if (shortcode) {
                    const freshMediaInfo = await fetchInstagramMedia(shortcode);
                    videoData = freshMediaInfo;
                    videoLink.videoInfo = freshMediaInfo;
                }
            } else if (isTikTok) {
                console.log('--- TikTok URL\'i olarak işleniyor...');
                const freshVideoInfo = await fetchTikTokVideoFromProxy(videoLink.originalUrl);
                videoData = freshVideoInfo;
                videoLink.videoInfo = freshVideoInfo;
            }
            await videoLink.save();
        } catch (err) {
            console.error('Veri güncelleme hatası:', err.message);
        }

        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const isDiscordOrTelegram = userAgent.includes('discordbot') || userAgent.includes('telegrambot');

        if (!noembedParam) {
            if (isDiscordOrTelegram) {
                let mediaUrl = null;
                if (isTikTok && videoData.play) {
                    mediaUrl = videoData.play;
                } else if (isInstagram && videoData.video_url) { // Tek video ise direkt yönlendir
                    mediaUrl = videoData.video_url;
                }
                if (mediaUrl) {
                    return res.redirect(307, mediaUrl);
                }
            }
        }

        let ogTags = '';
        const title = isInstagram
            ? `Instagram post by @${videoData.user?.username || 'unknown'}`
            : isTikTok
                ? `TikTok video by @${videoData.author?.unique_id || 'unknown'}`
                : `Video content`;

        const description = isInstagram
            ? (videoData.caption || "Instagram media")
            : isTikTok
                ? (videoData.desc || "TikTok video")
                : "Shared media";

        // Tek video varsa direkt yönlendir
        if (
            (isTikTok && videoData.play) ||
            (isInstagram && videoData.video_url)
        ) {
            return res.redirect(videoData.play || videoData.video_url || videoLink.originalUrl);
        }
        
        let ogImages = '';
        if (isInstagram && videoData.image_urls) {
            videoData.image_urls.forEach(imageUrl => {
                 ogImages += `<meta property="og:image" content="${imageUrl}" />\n`;
            });
        } else if (videoData.cover) {
            ogImages = `<meta property="og:image" content="${videoData.cover}" />`;
        }

        ogTags = `
            <!DOCTYPE html>
            <html>
              <head>
                <meta charset="utf-8">
                <title>${title}</title>
                <meta property="og:title" content="${title}" />
                <meta property="og:description" content="${description}" />
                ${ogImages}
                <meta name="twitter:card" content="summary_large_image" />
              </head>
              <body>
                <h1>${title}</h1>
                <p>${description}</p>
                <script>window.location.href = "${videoLink.originalUrl}"</script>
              </body>
            </html>
        `;

        res.send(ogTags);

    } catch (err) {
        console.error('ShortId route error:', err);
        res.status(500).send('Sunucu hatası');
    }
});

app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
