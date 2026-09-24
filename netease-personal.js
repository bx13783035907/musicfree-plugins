/*
 * 网易云个人账号 / MusicFree 0.1.12
 * Read-only account integration. Cookie is read from local plugin settings.
 * Protocol reference: NeteaseCloudMusicApiEnhanced/api-enhanced (MIT).
 * Copyright (c) 2013-2022 Binaryify
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

const axios = require('axios');
const CryptoJS = require('crypto-js');
const bigInt = require('big-integer');
const cheerio = require('cheerio');

const ORIGIN = 'https://music.163.com';
const CLIENT_ORIGIN = 'https://interfacepc.music.163.com';
const DIAGNOSTIC_PREFIX = '__netease_diagnostic_';
const DIAGNOSTIC_SONG = '167655'; // 许嵩《幻听》，通过网易云搜索确认
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const PAGE_SIZE = 30;
const TRACK_PAGE_SIZE = 50;
const VERSION = '0.1.12';
const MODULUS = 'e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7';
const READ_PATHS = [
  '/api/cloudsearch/pc', '/api/w/nuser/account/get', '/api/user/playlist',
  '/api/v6/playlist/detail', '/api/v3/song/detail', '/api/song/lyric',
  '/api/song/enhance/player/url/v1', '/api/song/enhance/player/url'
];
let activeFingerprint = '';
let accountCache = null;
let sheetCache = [];
let albumCache = [];
let biographyCache = [];
const songCache = new Map();
const personalListCache = new Map();
const catalogCache = new Map();
const discoveryCache = new Map();
const lyricCache = new Map();
const pendingReads = new Map();

function cacheGet(cache, key) {
  const entry = cache.get(key);
  if (entry && entry.expires > Date.now()) return entry.value;
  cache.delete(key);
  return undefined;
}

function cachePut(cache, key, value, ttl, limit) {
  cache.delete(key);
  cache.set(key, { value: value, expires: Date.now() + ttl });
  while (cache.size > limit) cache.delete(cache.keys().next().value);
}

async function shareRead(key, load) {
  if (pendingReads.has(key)) return pendingReads.get(key);
  if (pendingReads.size >= 24) return load();
  const pending = load();
  pendingReads.set(key, pending);
  try { return await pending; } finally {
    if (pendingReads.get(key) === pending) pendingReads.delete(key);
  }
}

function clearAccountCaches() {
  accountCache = null;
  sheetCache = [];
  albumCache = [];
  biographyCache = [];
  songCache.clear();
  personalListCache.clear();
  catalogCache.clear();
  lyricCache.clear();
  pendingReads.clear();
}

function settings() {
  const vars = typeof env !== 'undefined' && env.getUserVariables ? env.getUserVariables() : {};
  const raw = String((vars && vars.cookie) || '').trim();
  if (/[\r\n]/.test(raw)) throw new Error('Cookie 必须是一行，请复制 MUSIC_U 的值或完整 Cookie 请求头。');
  let cookie = raw.replace(/^Cookie\s*:\s*/i, '');
  // A single MUSIC_U value may contain '='; detect the named cookie explicitly.
  if (cookie && !/(?:^|;\s*)MUSIC_U=/.test(cookie)) {
    if (cookie.indexOf(';') >= 0 || /^(?:__csrf|MUSIC_A|os)=/.test(cookie)) {
      throw new Error('当前配置没有 MUSIC_U，请在网易云网页登录后重新获取。');
    }
    cookie = 'MUSIC_U=' + cookie;
  }
  if (cookie && !/(?:^|;\s*)MUSIC_U=[^;\s]+/.test(cookie)) {
    throw new Error('MUSIC_U 为空，请重新填写登录凭证。');
  }
  const fingerprint = CryptoJS.SHA256(cookie).toString();
  if (fingerprint !== activeFingerprint) {
    activeFingerprint = fingerprint;
    clearAccountCaches();
  }
  return { cookie: cookie, fingerprint: fingerprint, deadline: Date.now() + 8500 };
}

function pageNumber(page) {
  const n = page == null ? 1 : Number(page);
  if (!Number.isInteger(n) || n < 1) throw new Error('页码必须从 1 开始。');
  return n;
}

function mediaId(value) {
  const id = String(value == null ? '' : value);
  if (!/^[1-9][0-9]*$/.test(id)) throw new Error('歌曲或歌单 ID 无效。');
  return id;
}

function aes(text, key) {
  return CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(text), CryptoJS.enc.Utf8.parse(key), {
    iv: CryptoJS.enc.Utf8.parse('0102030405060708'),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  }).toString();
}

function encodeRequest(data) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let secret = '';
  for (let i = 0; i < 16; i += 1) secret += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  const reversedHex = CryptoJS.enc.Utf8.parse(secret.split('').reverse().join('')).toString();
  let rsa = bigInt(reversedHex, 16).modPow(65537, bigInt(MODULUS, 16)).toString(16);
  while (rsa.length < 256) rsa = '0' + rsa;
  const params = aes(aes(JSON.stringify(data), '0CoJUm6Qyw8W8jud'), secret);
  return 'params=' + encodeURIComponent(params) + '&encSecKey=' + rsa;
}

function encodeClientRequest(path, data) {
  const json = JSON.stringify(data);
  const digest = CryptoJS.MD5('nobody' + path + 'use' + json + 'md5forencrypt').toString();
  const text = path + '-36cd479b6b5-' + json + '-36cd479b6b5-' + digest;
  const encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(text), CryptoJS.enc.Utf8.parse('e82ckenh8dichen8'), {
    mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7
  });
  return 'params=' + encrypted.ciphertext.toString().toUpperCase();
}

function cookieValue(cookie, key) {
  const match = cookie.match(new RegExp('(?:^|;\\s*)' + key + '=([^;]*)'));
  return match ? match[1] : '';
}

async function request(path, payload, ctx, transport) {
  // Never reuse signed playback URLs or an explicit login check.
  if (path.indexOf('/api/song/enhance/') === 0 || path === '/api/w/nuser/account/get') {
    return sendRequest(path, payload, ctx, transport);
  }
  const key = ctx.fingerprint + '|' + path + '|' + (transport || 'web') + '|' + JSON.stringify(payload);
  const personal = path === '/api/user/playlist';
  const catalog = path === '/api/cloudsearch/pc' || /^\/api\/artist(?:\/albums)?\/[1-9][0-9]*$/.test(path);
  const cache = personal ? personalListCache : catalog ? catalogCache : null;
  const cached = cache ? cacheGet(cache, key) : undefined;
  if (cached) return cached;
  return shareRead(key, async function () {
    const body = await sendRequest(path, payload, ctx, transport);
    if (personal && Array.isArray(body.playlist) && activeFingerprint === ctx.fingerprint) {
      cachePut(personalListCache, key, body, 30000, 6);
    }
    if (catalog && activeFingerprint === ctx.fingerprint) {
      const field = { 1: 'songs', 10: 'albums', 100: 'artists', 1000: 'playlists' }[payload.type];
      const valid = path === '/api/cloudsearch/pc' ? Array.isArray(body.result && body.result[field]) :
        Array.isArray(path.indexOf('/albums/') >= 0 ? body.hotAlbums : body.hotSongs);
      if (valid) cachePut(catalogCache, key, body, 30000, 8);
    }
    return body;
  });
}

async function sendRequest(path, payload, ctx, transport) {
  // Dynamic read-only routes observed in the official website's core script.
  const catalogPath = /^\/api\/(?:v1\/album|artist(?:\/albums)?)\/[1-9][0-9]*$/.test(path);
  if (READ_PATHS.indexOf(path) < 0 && !catalogPath) throw new Error('不支持的接口。');
  if (transport === 'client' && path !== '/api/song/enhance/player/url/v1') throw new Error('不支持的客户端接口。');
  const remaining = ctx.deadline - Date.now();
  if (remaining < 100) throw new Error('本次加载超时，请稍后重试。');
  const match = ctx.cookie.match(/(?:^|;\s*)__csrf=([^;]*)/);
  const data = Object.assign({}, payload, { csrf_token: match ? match[1] : '', e_r: false });
  // axios 0.27's post() merges headers with an empty object. A normal object
  // created in MusicFree's VM fails axios's cross-realm isPlainObject check,
  // so that merge silently discards Cookie and all custom headers. A null
  // prototype is recognized in both realms, without changing axios globals.
  const headers = Object.assign(Object.create(null), {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': ORIGIN,
    'Referer': ORIGIN + '/',
    'User-Agent': UA
  });
  if (ctx.cookie) headers.Cookie = ctx.cookie;
  let url = ORIGIN + path.replace(/^\/api\//, '/weapi/');
  let encoded;
  if (transport === 'client') {
    // EAPI carries the same user credential in its encrypted header as well
    // as the HTTP Cookie. It is sent only to NetEase's fixed client endpoint.
    const clientHeader = {
      os: 'pc', appver: '3.1.17.204416', versioncode: '140',
      osver: 'Microsoft-Windows-10-Professional-build-19045-64bit',
      channel: 'netease', __csrf: cookieValue(ctx.cookie, '__csrf'),
      requestId: String(Date.now()) + '_' + String(Math.floor(Math.random() * 1000))
    };
    const token = cookieValue(ctx.cookie, 'MUSIC_U');
    if (token) clientHeader.MUSIC_U = token;
    data.header = clientHeader;
    headers.Cookie = Object.keys(clientHeader).map(function (key) {
      return encodeURIComponent(key) + '=' + encodeURIComponent(clientHeader[key]);
    }).join('; ');
    url = CLIENT_ORIGIN + path.replace(/^\/api\//, '/eapi/');
    encoded = encodeClientRequest(path, data);
  } else {
    // The official web client sends this query parameter even when empty.
    // A csrf_token only inside the encrypted body is not equivalent.
    url += '?csrf_token=' + encodeURIComponent(match ? match[1] : '');
    encoded = encodeRequest(data);
  }
  let response;
  try {
    response = await axios.post(url, encoded, {
      headers: headers,
      // React Native XHR defaults to credentials=true. Android's OkHttp jar
      // can then replace our explicit Cookie with an unrelated saved session.
      // Disable only automatic cookies; the explicit Cookie header stays sent.
      withCredentials: false,
      timeout: Math.min(6500, remaining),
      maxRedirects: 0,
      validateStatus: function () { return true; }
    });
  } catch (error) {
    // Never propagate an axios error: it includes request headers and Cookie.
    throw new Error('网易云请求失败或超时，请检查网络后重试。');
  }
  const body = response.data;
  const code = body && Number(body.code);
  if (response.status === 401 || code === 301 || code === 302 || code === 401) {
    if (activeFingerprint === ctx.fingerprint) clearAccountCaches();
    throw new Error('网易云登录已失效，请更新插件设置中的 Cookie。');
  }
  if (response.status === 403 || code === 403 || code === 405) {
    throw new Error('网易云拒绝了本次请求，请在官网确认账号状态并稍后重试。');
  }
  if (response.status !== 200 || !body || typeof body !== 'object' || code !== 200) {
    throw new Error('网易云接口返回异常（HTTP ' + response.status + '，状态 ' + (code || '未知') + '）。');
  }
  return body;
}

function musicItem(song) {
  const album = song.al || song.album || {};
  const artists = song.ar || song.artists || [];
  return {
    id: mediaId(song.id),
    title: song.name || '未命名歌曲',
    artist: artists.map(function (item) { return item.name; }).filter(Boolean).join(' / ') || '未知歌手',
    album: album.name || '',
    artwork: album.picUrl || '',
    duration: Math.max(0, Number(song.dt || song.duration || 0) / 1000)
  };
}

function sheetItem(sheet) {
  return {
    id: mediaId(sheet.id),
    title: sheet.name || '未命名歌单',
    artwork: sheet.coverImgUrl || '',
    artist: sheet.creator ? sheet.creator.nickname || '' : '',
    description: sheet.description || '',
    worksNum: Number(sheet.trackCount || 0),
    playCount: Number(sheet.playCount || 0)
  };
}

function albumItem(album) {
  const artists = album.artists && album.artists.length ? album.artists : album.artist ? [album.artist] : [];
  return {
    id: mediaId(album.id), title: album.name || '未命名专辑',
    artist: artists.map(function (artist) { return artist.name; }).filter(Boolean).join(' / ') || '未知歌手',
    artwork: album.picUrl || '', description: album.description || '',
    worksNum: Number(album.size || album.songCount || 0), createAt: Number(album.publishTime || 0)
  };
}

function artistItem(artist) {
  return {
    id: mediaId(artist.id), name: artist.name || '未知歌手',
    avatar: artist.picUrl || artist.img1v1Url || '',
    description: String(artist.briefDesc || '').trim()
  };
}

async function artistBiography(item, ctx) {
  return shareRead('biography|' + ctx.fingerprint + '|' + mediaId(item.id), function () { return loadArtistBiography(item, ctx); });
}

async function loadArtistBiography(item, ctx) {
  const id = mediaId(item.id);
  const cached = biographyCache.filter(function (entry) {
    return entry.id === id && entry.fingerprint === ctx.fingerprint && entry.expires > Date.now();
  })[0];
  if (cached) return cached.description;
  if (!ctx.cookie) return '登录后可查看歌手简介，请在插件设置中配置网易云 Cookie。';
  const remaining = ctx.deadline - Date.now();
  if (remaining < 150) return '简介暂时无法加载，请重新搜索后查看。';
  try {
    // This fixed page was observed via the official artist page's introduction
    // link. Parse only its public biography, never page-wide account metadata.
    const response = await axios.get(ORIGIN + '/artist/desc?id=' + id, {
      headers: Object.assign(Object.create(null), { Cookie: ctx.cookie, 'User-Agent': UA, Referer: ORIGIN + '/artist?id=' + id }),
      withCredentials: false,
      timeout: Math.min(1800, remaining), maxRedirects: 0, maxContentLength: 1024 * 1024,
      validateStatus: function () { return true; }
    });
    if (response.status !== 200 || typeof response.data !== 'string') throw new Error('Biography unavailable');
    const $ = cheerio.load(response.data);
    const section = $('.n-artdesc').first();
    if (!section.length) throw new Error('Biography unavailable');
    const paragraph = section.find('p').first().clone();
    paragraph.find('script,style').remove();
    paragraph.find('br').replaceWith('\n');
    const description = paragraph.text().replace(/\u00a0/g, ' ').trim() || '网易云暂未提供该歌手的个人简介。';
    if (activeFingerprint === ctx.fingerprint) {
      biographyCache = biographyCache.filter(function (entry) { return entry.id !== id && entry.expires > Date.now(); }).slice(-99);
      biographyCache.push({ id: id, fingerprint: ctx.fingerprint, expires: Date.now() + 600000, description: description });
    }
    return description;
  } catch (error) {
    // An optional biography must not hide search results or expose axios data.
    return '简介暂时无法加载，请重新搜索后查看。';
  }
}

async function addArtistBiographies(items, ctx) {
  // MusicFree takes the artist header from the search result and does not merge
  // artist metadata returned by getArtistWorks. Enrich before returning results.
  const bioContext = Object.assign({}, ctx, { deadline: Math.min(ctx.deadline, Date.now() + 5000) });
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const item = items[cursor++];
      if (!item.description) item.description = await artistBiography(item, bioContext);
    }
  }
  await Promise.all([worker(), worker(), worker()]);
  return items;
}

async function albumPage(item, page, ctx) {
  const id = mediaId(item.id);
  const current = pageNumber(page);
  const cached = albumCache.filter(function (entry) {
    return entry.id === id && entry.fingerprint === ctx.fingerprint && entry.expires > Date.now();
  })[0];
  const body = cached ? cached.body : await request('/api/v1/album/' + id, {}, ctx);
  if (!body.album || !Array.isArray(body.songs)) throw new Error('网易云未返回完整专辑数据，请稍后重试。');
  if (!cached && activeFingerprint === ctx.fingerprint) {
    albumCache = albumCache.filter(function (entry) { return entry.id !== id && entry.expires > Date.now(); }).slice(-5);
    albumCache.push({ id: id, fingerprint: ctx.fingerprint, expires: Date.now() + 60000, body: body });
  }
  const offset = (current - 1) * TRACK_PAGE_SIZE;
  rememberSongs(body.songs.slice(offset, offset + TRACK_PAGE_SIZE), ctx);
  return {
    isEnd: offset + TRACK_PAGE_SIZE >= body.songs.length,
    albumItem: albumItem(body.album),
    musicList: body.songs.slice(offset, offset + TRACK_PAGE_SIZE).map(musicItem)
  };
}

async function account(ctx, fresh) {
  if (!ctx.cookie) throw new Error('请先在插件设置中填写网易云 Cookie，再打开个人歌单。');
  if (fresh) return loadAccount(ctx);
  if (accountCache && accountCache.fingerprint === ctx.fingerprint && accountCache.expires > Date.now()) return accountCache.uid;
  return shareRead('account|' + ctx.fingerprint, function () { return loadAccount(ctx); });
}

async function loadAccount(ctx) {
  // Match the account endpoint observed in the official website.
  const body = await request('/api/w/nuser/account/get', {}, ctx);
  const uid = body.profile && body.profile.userId || body.account && body.account.id;
  if (!uid) throw new Error('未识别到网易云账号，请更新 Cookie 后重试。');
  if (activeFingerprint === ctx.fingerprint) accountCache = { uid: String(uid), fingerprint: ctx.fingerprint, expires: Date.now() + 300000 };
  return String(uid);
}

async function lyrics(item, ctx) {
  const id = mediaId(item.id);
  const key = ctx.fingerprint + '|' + id;
  let result = cacheGet(lyricCache, key);
  if (!result) {
    const body = await request('/api/song/lyric', { id: id, lv: -1, tv: -1, rv: -1, kv: -1, _nmclfl: 1 }, ctx);
    const raw = body.lrc && body.lrc.lyric;
    const translation = body.tlyric && body.tlyric.lyric;
    result = { rawLrc: typeof raw === 'string' ? raw : '', translation: typeof translation === 'string' ? translation : '' };
    // Empty/malformed replies may be transient. Only explicit instrumental
    // responses or real text qualify; cap both item count and text size.
    if ((result.rawLrc || result.translation || body.nolyric === true) &&
      result.rawLrc.length + result.translation.length <= 65536 && activeFingerprint === ctx.fingerprint) {
      cachePut(lyricCache, key, result, 300000, 40);
    }
  }
  return Object.assign({}, result);
}

async function personalSheets(uid, page, limit, ctx) {
  const body = await request('/api/user/playlist', { uid: uid, limit: limit, offset: (page - 1) * limit, includeVideo: false }, ctx);
  if (!Array.isArray(body.playlist)) throw new Error('无法读取个人歌单，请更新 Cookie 后重试。');
  return body;
}

function likedSheets(sheets, uid) {
  return sheets.filter(function (sheet) {
    return Number(sheet.specialType) === 5 && sheet.creator && String(sheet.creator.userId) === uid;
  });
}

async function playlist(id, ctx, allTracks) {
  const key = mediaId(id);
  const cached = sheetCache.filter(function (entry) {
    return entry.id === key && entry.fingerprint === ctx.fingerprint && entry.expires > Date.now();
  })[0];
  if (cached && (!allTracks || cached.allTracks ||
    (Array.isArray(cached.sheet.tracks) && cached.sheet.tracks.length >= cached.sheet.trackIds.length))) return cached.sheet;
  // n limits embedded song details, while trackIds keeps the complete order.
  // Full imports retain the larger response to avoid a second bulk lookup.
  const result = await request('/api/v6/playlist/detail', { id: key, n: allTracks ? 100000 : TRACK_PAGE_SIZE, s: 0 }, ctx);
  const sheet = result.playlist;
  if (!sheet || !Array.isArray(sheet.trackIds)) throw new Error('无法读取完整歌单，请确认登录状态和歌单访问权限。');
  if (Number(sheet.trackCount) > sheet.trackIds.length) throw new Error('网易云只返回了部分歌单，请更新 Cookie 后重试。');
  if (activeFingerprint === ctx.fingerprint) {
    const fuller = sheetCache.filter(function (entry) { return entry.id === key && entry.allTracks && entry.expires > Date.now(); })[0];
    if (allTracks || !fuller) {
      sheetCache = sheetCache.filter(function (entry) { return entry.id !== key && entry.expires > Date.now(); }).slice(-5);
      sheetCache.push({ id: key, fingerprint: ctx.fingerprint, expires: Date.now() + 60000, sheet: sheet, allTracks: !!allTracks });
    }
  }
  return sheet;
}

function completeSong(song) {
  return !!(song && /^[1-9][0-9]*$/.test(String(song.id)) && song.name &&
    Array.isArray(song.ar || song.artists) && (song.al || song.album) &&
    Number.isFinite(Number(song.dt == null ? song.duration : song.dt)));
}

function rememberSongs(songs, ctx) {
  if (activeFingerprint !== ctx.fingerprint) return;
  songs.forEach(function (song) {
    if (completeSong(song)) {
      const key = ctx.fingerprint + '|' + song.id;
      if (!cacheGet(songCache, key)) cachePut(songCache, key, musicItem(song), 60000, 400);
    }
  });
}

async function songsByIds(ids, ctx, knownSongs) {
  if (!ids.length) return [];
  const normalized = ids.map(mediaId);
  const byId = {};
  const wanted = new Set(normalized);
  // Reuse only complete metadata from the playlist response. Missing or partial
  // entries are still fetched, in original trackIds order, without truncation.
  (knownSongs || []).forEach(function (song) {
    if (completeSong(song) && wanted.has(String(song.id))) {
      byId[String(song.id)] = musicItem(song);
    }
  });
  normalized.forEach(function (id) {
    if (!byId[id]) byId[id] = cacheGet(songCache, ctx.fingerprint + '|' + id);
  });
  const missing = Array.from(wanted).filter(function (id) { return !byId[id]; });
  if (missing.length) {
    const result = await request('/api/v3/song/detail', {
      c: '[' + missing.map(function (id) { return '{"id":' + id + '}'; }).join(',') + ']'
    }, ctx);
    if (!Array.isArray(result.songs)) throw new Error('网易云未返回歌曲详情。');
    result.songs.forEach(function (song) { if (wanted.has(String(song.id))) byId[String(song.id)] = musicItem(song); });
  }
  if (activeFingerprint === ctx.fingerprint) {
    Object.keys(byId).forEach(function (id) {
      if (byId[id] && !cacheGet(songCache, ctx.fingerprint + '|' + id)) {
        cachePut(songCache, ctx.fingerprint + '|' + id, byId[id], 60000, 400);
      }
    });
  }
  // MusicFree may decorate returned items. Keep its mutations out of the cache.
  return normalized.filter(function (id) { return !!byId[id]; }).map(function (id) { return Object.assign({}, byId[id]); });
}

async function sheetPage(item, page, ctx) {
  const current = pageNumber(page);
  const sheet = await playlist(item.id, ctx);
  const offset = (current - 1) * TRACK_PAGE_SIZE;
  const ids = sheet.trackIds.slice(offset, offset + TRACK_PAGE_SIZE).map(function (track) { return track.id; });
  return {
    isEnd: offset + TRACK_PAGE_SIZE >= sheet.trackIds.length,
    sheetItem: sheetItem(sheet),
    musicList: await songsByIds(ids, ctx, Array.isArray(sheet.tracks) ? sheet.tracks : [])
  };
}

// Public discovery pages observed on music.163.com. Never attach account
// credentials to these requests, or follow a URL supplied by a page or tag.
async function discoveryPage(kind, page) {
  const current = pageNumber(page);
  const path = kind === 'charts' ? '/discover/toplist' : current === 1 ? '/discover/playlist' :
    '/discover/playlist/?order=hot&cat=' + encodeURIComponent('全部') + '&limit=35&offset=' + ((current - 1) * 35);
  let response;
  try {
    response = await axios.get(ORIGIN + path, {
      headers: Object.assign(Object.create(null), { 'User-Agent': UA, Referer: ORIGIN + '/' }),
      withCredentials: false,
      timeout: 6500, maxRedirects: 0, maxContentLength: 2000000,
      validateStatus: function () { return true; }
    });
  } catch (error) {
    throw new Error('网易云公开歌单加载失败，请检查网络后重试。');
  }
  if (response.status !== 200 || typeof response.data !== 'string') {
    throw new Error('网易云公开歌单暂时不可用，请稍后重试。');
  }
  return cheerio.load(response.data);
}

function publicArtwork(value) {
  return /^https?:\/\//i.test(value || '') ? value.replace(/^http:/i, 'https:') : '';
}

async function cachedDiscovery(key, load) {
  let value = cacheGet(discoveryCache, key);
  if (!value) value = await shareRead('discovery|' + key, async function () {
    const result = await load();
    cachePut(discoveryCache, key, result, 60000, 12);
    return result;
  });
  return JSON.parse(JSON.stringify(value));
}

async function publicSheets(page) {
  const current = pageNumber(page);
  return cachedDiscovery('sheets|' + current, function () { return loadPublicSheets(current); });
}

async function loadPublicSheets(page) {
  const $ = await discoveryPage('sheets', page);
  const data = [];
  $('.m-cvrlst li').each(function (_, element) {
    const row = $(element);
    const link = row.find('a.msk').first();
    const match = (link.attr('href') || '').match(/^\/playlist\?id=([1-9][0-9]*)$/);
    if (!match) return;
    data.push({ id: match[1], title: link.attr('title') || row.find('.dec').text().trim(),
      artist: row.find('a.nm').text().trim(), artwork: publicArtwork(row.find('.u-cover img').attr('src')) });
  });
  if (!data.length) throw new Error('网易云未返回公开推荐歌单，请稍后重试。');
  return { isEnd: !$('.u-page .znxt:not(.js-disabled)[href^="/discover/playlist"]').length, data: data };
}

async function topLists() {
  return cachedDiscovery('charts', loadTopLists);
}

async function loadTopLists() {
  const $ = await discoveryPage('charts', 1);
  const groups = [];
  $('.n-minelst > ul').each(function (_, element) {
    const list = $(element);
    const data = [];
    list.find('li').each(function (_, rowElement) {
      const row = $(rowElement);
      const link = row.find('.name a').first();
      const match = (link.attr('href') || '').match(/^\/discover\/toplist\?id=([1-9][0-9]*)$/);
      if (!match) return;
      data.push({ id: match[1], title: link.text().trim(),
        artwork: publicArtwork(row.find('img').first().attr('src')), description: row.find('p.s-fc4').text().trim() });
    });
    if (data.length) groups.push({ title: list.prev('h2').text().trim() || '网易云榜单', data: data });
  });
  if (!groups.length) throw new Error('网易云未返回榜单，请稍后重试。');
  return groups;
}

function idFromInput(input, kind) {
  const text = String(input || '').trim();
  if (/^[1-9][0-9]*$/.test(text)) return text;
  // Parse known full URLs only. Never fetch a user-supplied URL with Cookie.
  const host = text.match(/^https?:\/\/([^/?#]+)\//i);
  if (!host || !/^(?:music\.163\.com|y\.music\.163\.com)$/i.test(host[1])) {
    throw new Error('请粘贴网易云完整' + (kind === 'song' ? '歌曲' : '歌单') + '链接或数字 ID（暂不支持短链接）。');
  }
  const path = new RegExp('(?:/|#/)'+ kind + '(?:\\?|/|$)');
  const query = text.match(/[?&]id=([1-9][0-9]*)(?:[&#]|$)/);
  if (path.test(text) && query) return query[1];
  throw new Error('链接类型或 ID 无效，请复制网易云完整链接。');
}

function playbackSource(body, id) {
  return Array.isArray(body.data) && body.data.filter(function (entry) {
    return String(entry.id) === id;
  })[0];
}

function isTrial(source) {
  // freeTrialPrivilege describes trial eligibility; it is not itself proof
  // that a successful playback URL is a clipped preview.
  return !!(source && source.freeTrialInfo && source.freeTrialInfo !== 'null');
}

function playable(source) {
  return !!(source && Number(source.code) === 200 &&
    typeof source.url === 'string' && /^https?:\/\//i.test(source.url) && !isTrial(source));
}

function playbackSummary(source) {
  if (!source) return '无歌曲数据';
  // Only emit bounded numeric fields and our own labels. Never print URLs,
  // server messages, account IDs, headers, or arbitrary response objects.
  const raw = source.code;
  const status = (typeof raw === 'number' || typeof raw === 'string') && /^-?\d{1,6}$/.test(String(raw)) ? String(raw) : '未知';
  return '状态=' + status + '、地址=' + (source.url ? '有' : '无') + '、试听=' + (isTrial(source) ? '是' : '否');
}

async function mediaSource(item, quality) {
  const ctx = settings();
  const id = mediaId(item.id);
  const levels = { low: 'standard', standard: 'standard', high: 'exhigh', super: 'lossless' };
  const level = levels[quality] || 'standard';
  const body = await request('/api/song/enhance/player/url/v1', {
    ids: '[' + id + ']', level: level, encodeType: level === 'lossless' ? 'flac' : 'mp3'
  }, ctx, ctx.cookie ? 'client' : undefined);
  let source = playbackSource(body, id);
  const firstSummary = playbackSummary(source);
  let loginStatus = ctx.cookie ? '未验证' : '未配置';
  let fallbackSummary = '未尝试';
  if (!playable(source) && ctx.cookie) {
    // A stored string is not proof of an authenticated session. Verify it
    // before the compatibility request, using the same credential snapshot.
    await account(ctx);
    loginStatus = '已识别';
    if (ctx.deadline - Date.now() > 500) {
      const fallback = await request('/api/song/enhance/player/url/v1', {
        ids: '[' + id + ']', level: level, encodeType: level === 'lossless' ? 'flac' : 'mp3'
      }, ctx);
      const alternative = playbackSource(fallback, id);
      fallbackSummary = playbackSummary(alternative);
      if (playable(alternative)) source = alternative;
    } else {
      fallbackSummary = '时间不足';
    }
  }
  if (!playable(source)) {
    const reason = isTrial(source) ? '网易云当前只提供试听片段。' : '网易云未返回可用整曲音源。';
    throw new Error(reason + '请确认同一账号能否在官方 App 完整播放。诊断：登录=' + loginStatus +
      '；音质=' + level + '；主接口[' + firstSummary + ']；兼容接口[' + fallbackSummary + ']。');
  }
  // Playback/CDN requests must never receive the account Cookie.
  return { url: source.url, headers: { 'user-agent': UA, 'Referer': ORIGIN + '/' } };
}

function diagnosticFailure(error) {
  const text = error && error.message || '';
  if (/登录已失效|未识别到网易云账号/.test(text)) return '登录未生效，需核对凭证是否发送成功';
  if (/Cookie|MUSIC_U/.test(text)) return 'Cookie 未配置或格式不正确';
  if (/超时|请求失败/.test(text)) return '网络请求失败或超时';
  if (/拒绝/.test(text)) return '网易云拒绝请求，请检查官网账号状态';
  return '接口异常，未取得有效结果';
}

function accountCheckRow(index, title, detail) {
  return { id: DIAGNOSTIC_PREFIX + 'account_' + index, title: title,
    description: detail || title, artist: '账号检查 · v' + VERSION, worksNum: 0 };
}

async function diagnoseAccount() {
  // Short titles remain readable in Android's three-column, two-line cards.
  const rows = [accountCheckRow(0, '账号检查 v' + VERSION, '下方卡片就是结果，无需点开。')];
  let ctx;
  try { ctx = settings(); } catch (_) {
    rows.push(accountCheckRow(1, 'Cookie 格式错误', '请在本机插件设置检查 MUSIC_U 值或完整 Cookie，不要发送凭证。'));
    return rows;
  }
  rows.push(accountCheckRow(1, ctx.cookie ? 'Cookie 已读取' : 'Cookie 未配置'));
  if (!ctx.cookie) return rows;
  let uid;
  try {
    accountCache = null;
    uid = await account(ctx, true);
    rows.push(accountCheckRow(2, '登录检查成功'));
  } catch (error) {
    const failure = diagnosticFailure(error);
    const title = /登录未生效/.test(failure) ? '登录未识别' : /网络/.test(failure) ? '登录请求超时或失败' : /拒绝/.test(failure) ? '登录请求被拒绝' : '登录接口异常';
    rows.push(accountCheckRow(2, title, failure));
    return rows;
  }
  try {
    // An explicit diagnostic must contact the server, not reuse list metadata.
    const body = await sendRequest('/api/user/playlist', { uid: uid, limit: 30, offset: 0, includeVideo: false }, ctx);
    if (!Array.isArray(body.playlist)) throw new Error('歌单数据缺失');
    rows.push(accountCheckRow(3, '歌单读取成功', '个人歌单接口已返回有效列表。'));
  } catch (error) {
    const failure = diagnosticFailure(error);
    rows.push(accountCheckRow(3, /网络/.test(failure) ? '歌单请求超时或失败' : /登录未生效/.test(failure) ? '歌单登录未识别' : /拒绝/.test(failure) ? '歌单请求被拒绝' : '歌单接口异常', failure));
  }
  return rows;
}

async function diagnosePlayback(song) {
  const targetId = song === 'sudi' ? '167691' : DIAGNOSTIC_SONG;
  const targetTitle = song === 'sudi' ? '天龙八部之宿敌' : '幻听';
  const rows = [];
  function add(title, detail) {
    rows.push({
      id: DIAGNOSTIC_PREFIX + targetId + '_' + String(rows.length + 1),
      title: title, description: detail || title,
      artist: '诊断报告 · v' + VERSION, worksNum: 0
    });
  }
  add(VERSION + ' · 许嵩《' + targetTitle + '》播放诊断', '测试歌曲 ID：' + targetId + '。仅检查登录和标准音质播放地址，不下载音频。结果不含账号凭证。');
  let ctx;
  try { ctx = settings(); } catch (error) {
    add('Cookie：格式不正确', diagnosticFailure(error));
    return rows;
  }
  add(ctx.cookie ? 'Cookie：插件已读到配置' : 'Cookie：插件未读到配置');
  if (!ctx.cookie) return rows;
  try {
    // Bypass the account cache so this report reflects a fresh server check.
    accountCache = null;
    await account(ctx, true);
    add('登录：网易云已识别账号', '账号已识别不等于每首歌曲、每档音质均有权限。');
  } catch (error) {
    add('登录：' + diagnosticFailure(error));
    return rows;
  }
  const transports = [{ name: '网页播放', value: undefined }, { name: '客户端播放', value: 'client' }];
  for (let i = 0; i < transports.length; i += 1) {
    const transport = transports[i];
    try {
      const body = await request('/api/song/enhance/player/url/v1', {
        ids: '[' + targetId + ']', level: 'standard', encodeType: 'mp3'
      }, ctx, transport.value);
      const source = playbackSource(body, targetId);
      add(transport.name + '：' + (playable(source) ? '已取得整曲地址' : playbackSummary(source)),
        playbackSummary(source) + '。此结果只验证音源接口，不代表播放器已成功解码。');
    } catch (error) {
      add(transport.name + '：' + diagnosticFailure(error));
    }
  }
  add('请截取这些结果用于排查', '报告仅含固定说明和状态码，不包含 Cookie、账号 ID 或音频地址。无需点击播放诊断条目。');
  return rows;
}

module.exports = {
  platform: '网易云个人账号',
  version: VERSION,
  srcUrl: 'https://raw.githubusercontent.com/bx13783035907/musicfree-plugins/main/netease-personal.js',
  author: '个人自用',
  primaryKey: ['id'],
  cacheControl: 'no-store',
  supportedSearchType: ['music', 'album', 'artist', 'sheet'],
  userVariables: [{
    key: 'cookie',
    title: '网易云 Cookie / MUSIC_U',
    name: '网易云 Cookie / MUSIC_U',
    hint: '填写 MUSIC_U 值或完整 Cookie；不要公开分享。'
  }],
  hints: {
    importMusicItem: ['支持网易云完整歌曲链接或数字 ID，暂不支持短链接。'],
    importMusicSheet: ['支持网易云完整歌单链接或数字 ID。超过 1000 首请从推荐歌单入口分页浏览。']
  },

  async search(query, page, type) {
    const categories = {
      music: { code: 1, list: 'songs', total: 'songCount', map: musicItem },
      album: { code: 10, list: 'albums', total: 'albumCount', map: albumItem },
      artist: { code: 100, list: 'artists', total: 'artistCount', map: artistItem },
      sheet: { code: 1000, list: 'playlists', total: 'playlistCount', map: sheetItem }
    };
    if (!Object.prototype.hasOwnProperty.call(categories, type)) return { isEnd: true, data: [] };
    const category = categories[type];
    const keyword = String(query || '').trim();
    if (!keyword) return { isEnd: true, data: [] };
    if (type === 'sheet' && /^(?:账号检查|账号诊断|播放诊断|宿敌诊断)$/.test(keyword)) {
      return { isEnd: true, data: pageNumber(page) > 1 ? [] :
        /^(?:账号检查|账号诊断)$/.test(keyword) ? await diagnoseAccount() : await diagnosePlayback(keyword === '宿敌诊断' ? 'sudi' : undefined) };
    }
    const ctx = settings();
    const offset = (pageNumber(page) - 1) * PAGE_SIZE;
    const body = await request('/api/cloudsearch/pc', {
      s: keyword, type: category.code,
      limit: PAGE_SIZE, offset: offset, total: true
    }, ctx);
    const result = body.result;
    if (!result) throw new Error('网易云搜索响应不完整，请稍后重试。');
    const list = result[category.list] || [];
    const total = result[category.total];
    if (!Array.isArray(list)) throw new Error('网易云搜索结果格式异常，请稍后重试。');
    const data = list.map(category.map);
    if (type === 'music') rememberSongs(list, ctx);
    if (type === 'artist') await addArtistBiographies(data, ctx);
    return {
      isEnd: list.length === 0 || (typeof total === 'number' ? offset + list.length >= total : list.length < PAGE_SIZE),
      data: data
    };
  },

  async getMediaSource(item, quality) {
    return mediaSource(item, quality);
  },

  async getLyric(item) {
    return lyrics(item, settings());
  },

  async getMusicInfo(item) {
    const songs = await songsByIds([item.id], settings());
    if (!songs.length) throw new Error('歌曲不存在或暂时不可访问。');
    return songs[0];
  },

  async getAlbumInfo(item, page) {
    return albumPage(item, page, settings());
  },

  async getArtistWorks(item, page, type) {
    if (type !== 'music' && type !== 'album') return { isEnd: true, data: [] };
    const id = mediaId(item.id);
    const current = pageNumber(page);
    // The public artist page exposes the hot-song list, not all songs.
    if (type === 'music') {
      if (current > 1) return { isEnd: true, data: [] };
      const ctx = settings();
      const body = await request('/api/artist/' + id, {}, ctx);
      if (!Array.isArray(body.hotSongs)) throw new Error('网易云未返回歌手热门歌曲，请稍后重试。');
      rememberSongs(body.hotSongs, ctx);
      return { isEnd: true, data: body.hotSongs.map(musicItem) };
    }
    const offset = (current - 1) * PAGE_SIZE;
    const body = await request('/api/artist/albums/' + id, { limit: PAGE_SIZE, offset: offset, total: true }, settings());
    if (!Array.isArray(body.hotAlbums)) throw new Error('网易云未返回歌手专辑，请稍后重试。');
    const total = typeof body.size === 'number' ? body.size : body.artist && body.artist.albumSize;
    return {
      isEnd: body.hotAlbums.length === 0 || (typeof body.more === 'boolean' ? !body.more : typeof total === 'number' ? offset + body.hotAlbums.length >= total : body.hotAlbums.length < PAGE_SIZE),
      data: body.hotAlbums.map(albumItem)
    };
  },

  async getRecommendSheetTags() {
    const checks = [{ id: 'account-check', title: '账号检查' }, { id: 'sudi-check', title: '宿敌诊断' }, { id: 'diagnostic', title: '播放诊断' }];
    return { pinned: [checks[0], { id: 'public', title: '热门歌单' }, { id: 'my', title: '我的歌单' }, { id: 'liked', title: '我喜欢的音乐' }, checks[1], checks[2]],
      data: [{ title: '问题排查', data: checks }] };
  },

  async getRecommendSheetsByTag(tag, page) {
    if (!tag || !tag.id || tag.id === 'public') return publicSheets(page);
    if (tag.id === 'account-check') return { isEnd: true, data: pageNumber(page) > 1 ? [] : await diagnoseAccount() };
    if (tag.id === 'sudi-check') return { isEnd: true, data: pageNumber(page) > 1 ? [] : await diagnosePlayback('sudi') };
    if (tag && tag.id === 'diagnostic') {
      return { isEnd: true, data: pageNumber(page) > 1 ? [] : await diagnosePlayback() };
    }
    if (tag.id !== 'my' && tag.id !== 'liked') throw new Error('不支持的歌单分类，请重新选择分类。');
    const ctx = settings();
    const current = pageNumber(page);
    const liked = tag && tag.id === 'liked';
    if (liked && current > 1) return { isEnd: true, data: [] };
    const uid = await account(ctx);
    const body = await personalSheets(uid, current, PAGE_SIZE, ctx);
    if (liked) {
      let matches = likedSheets(body.playlist, uid);
      // Share the first-page query with the normal list. Retain the previous
      // 1000-entry lookup as a fallback when the liked sheet is not on page 1.
      if (!matches.length && body.more !== false) {
        matches = likedSheets((await personalSheets(uid, 1, 1000, ctx)).playlist, uid);
      }
      if (!matches.length) throw new Error('未找到“我喜欢的音乐”歌单，请在“我的歌单”分类中查找。');
      return { isEnd: true, data: matches.map(sheetItem) };
    }
    return { isEnd: body.more === false || body.playlist.length < PAGE_SIZE, data: body.playlist.map(sheetItem) };
  },

  async getMusicSheetInfo(item, page) {
    if (String(item.id).indexOf(DIAGNOSTIC_PREFIX) === 0) {
      return { isEnd: true, sheetItem: item, musicList: [] };
    }
    return sheetPage(item, page, settings());
  },

  async getTopLists() {
    return topLists();
  },

  async getTopListDetail(item, page) {
    const result = await sheetPage(item, page, settings());
    return { isEnd: result.isEnd, musicList: result.musicList, topListItem: result.sheetItem };
  },

  async importMusicItem(input) {
    const songs = await songsByIds([idFromInput(input, 'song')], settings());
    if (!songs.length) throw new Error('歌曲不存在或暂时不可访问。');
    return songs[0];
  },

  async importMusicSheet(input) {
    const ctx = settings();
    const sheet = await playlist(idFromInput(input, 'playlist'), ctx, true);
    if (sheet.trackIds.length > 1000) throw new Error('歌单超过 1000 首，请从推荐歌单入口分页浏览，避免导入超时。');
    return songsByIds(sheet.trackIds.map(function (track) { return track.id; }), ctx, Array.isArray(sheet.tracks) ? sheet.tracks : []);
  }
};
