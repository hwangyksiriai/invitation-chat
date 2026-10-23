import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));

function readLocalEnv() {
  const filename = path.join(root, '.env.local');
  if (!fs.existsSync(filename)) return;
  for (const line of fs.readFileSync(filename, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([A-Z_]+)=(.*)$/);
    if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2];
  }
}

readLocalEnv();
const pin = process.env.INVITE_PIN;
if (!pin) throw new Error('INVITE_PIN is required.');
const secret = process.env.INVITE_SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const sessionHours = 8;
const attempts = new Map();

function constantTimeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function signature(expires) {
  return crypto.createHmac('sha256', secret).update(`invite:${expires}`).digest('hex');
}

export function makeSession(now = Date.now()) {
  const expires = now + sessionHours * 60 * 60 * 1000;
  return `${expires}.${signature(expires)}`;
}

export function validSession(value, now = Date.now()) {
  const match = String(value || '').match(/^(\d{13})\.([0-9a-f]{64})$/);
  if (!match || Number(match[1]) <= now) return false;
  return constantTimeEqual(signature(match[1]), match[2]);
}

function html(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, private',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  res.end(body);
}

function loginPage(message = '') {
  const safeMessage = message ? '<p class="error" role="alert">비밀번호를 다시 확인해 주세요.</p>' : '';
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Private Invitation</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#e9e9de;color:#20332a;font-family:Arial,"Malgun Gothic",sans-serif}.panel{width:min(440px,calc(100% - 40px));padding:54px 42px;background:#f7f6ef;border:1px solid #d7dace;box-shadow:0 26px 70px #41584522;text-align:center}.mark{font-size:11px;letter-spacing:.28em;color:#719179}.line{width:1px;height:54px;background:#b3c5b4;margin:32px auto}h1{font-family:Georgia,"Batang",serif;font-size:45px;font-weight:400;line-height:1.15;letter-spacing:-.055em;margin:0 0 18px}p{font-size:14px;line-height:1.8;color:#64716a;margin:0 0 30px}label{display:block;font-size:11px;letter-spacing:.12em;text-align:left;margin-bottom:9px}input{width:100%;height:52px;padding:0 16px;background:#fff;border:1px solid #cbd5cb;border-radius:0;font-size:18px;letter-spacing:.2em;text-align:center;color:#20332a}input:focus{outline:2px solid #83a98c;outline-offset:2px}button{width:100%;height:52px;margin-top:12px;border:0;background:#203b2d;color:white;font-size:12px;letter-spacing:.15em;cursor:pointer}.error{color:#a13a36;margin:14px 0 0}.foot{margin-top:28px;font-size:10px;letter-spacing:.1em;color:#98a098}</style></head><body><div class="panel"><div class="mark">PRIVATE CREATOR INVITATION</div><div class="line"></div><h1>당신만을 위한<br>초대장</h1><p>전달받으신 비밀번호를 입력하면<br>초대장을 확인하실 수 있습니다.</p><form method="post" action="/unlock"><label for="pin">ACCESS CODE</label><input id="pin" name="pin" type="password" inputmode="numeric" autocomplete="off" maxlength="20" required autofocus><button type="submit">초대장 열기 &nbsp; ↗</button>${safeMessage}</form><div class="foot">A PRIVATE SKINCARE EXPERIENCE</div></div></body></html>`;
}

function getCookie(req, key) {
  const cookie = req.headers.cookie || '';
  const part = cookie.split(';').map(x => x.trim()).find(x => x.startsWith(`${key}=`));
  return part ? part.slice(key.length + 1) : '';
}

function redirect(res, location, cookie) {
  const headers = { Location: location, 'Cache-Control': 'no-store' };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(303, headers);
  res.end();
}

export async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'POST' && url.pathname === '/unlock') {
    const ip = req.socket.remoteAddress || 'unknown';
    const record = attempts.get(ip) || { count: 0, until: 0 };
    if (record.until > Date.now()) return html(res, 429, loginPage('invalid'));
    let body = '';
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 4096) return html(res, 413, loginPage('invalid'));
    }
    const entered = new URLSearchParams(body).get('pin') || '';
    if (!constantTimeEqual(entered, pin)) {
      record.count += 1;
      if (record.count >= 5) { record.count = 0; record.until = Date.now() + 15 * 60 * 1000; }
      attempts.set(ip, record);
      return html(res, 401, loginPage('invalid'));
    }
    attempts.delete(ip);
    const secure = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
    return redirect(res, '/', `invite_session=${makeSession()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionHours * 3600}${secure ? '; Secure' : ''}`);
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') return html(res, 405, loginPage());
  if (url.pathname !== '/') return html(res, 404, loginPage());
  if (!validSession(getCookie(req, 'invite_session'))) return html(res, 200, loginPage());
  return html(res, 200, fs.readFileSync(path.join(root, 'index.html'), 'utf8'));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT) || 3000;
  http.createServer(handler).listen(port, '127.0.0.1', () => console.log(`Private invitation running at http://127.0.0.1:${port}`));
}

