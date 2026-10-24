// TOTP (RFC 6238) desde cero. Solo usamos crypto-js para el HMAC-SHA1 (permitido por el enunciado).
import CryptoJS from 'crypto-js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Base32 -> hex (decodificación manual, 5 bits por carácter)
export function base32ToHex(base32) {
  const clean = base32.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = '';
  for (const ch of clean) {
    const val = ALPHABET.indexOf(ch);
    if (val === -1) throw new Error(`Carácter Base32 inválido: ${ch}`);
    bits += val.toString(2).padStart(5, '0');
  }
  let hex = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    hex += parseInt(bits.slice(i, i + 8), 2).toString(16).padStart(2, '0');
  }
  return hex;
}

export function generateTOTP(secret, nowMs = Date.now(), step = 30, digits = 6) {
  const counter = Math.floor(nowMs / 1000 / step);                     // T = UnixTime // 30
  const counterHex = counter.toString(16).padStart(16, '0');            // 8 bytes big-endian
  const key = CryptoJS.enc.Hex.parse(base32ToHex(secret));
  const msg = CryptoJS.enc.Hex.parse(counterHex);
  const hmac = CryptoJS.HmacSHA1(msg, key).toString(CryptoJS.enc.Hex); // 20 bytes = 40 hex
  const offset = parseInt(hmac.slice(-1), 16);                          // truncamiento dinámico
  const binary = parseInt(hmac.substr(offset * 2, 8), 16) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function secondsRemaining(nowMs = Date.now(), step = 30) {
  return step - (Math.floor(nowMs / 1000) % step);
}

// Extrae el parámetro secret de otpauth://totp/Issuer:cuenta?secret=XXXX&issuer=...
export function parseOtpauth(uri) {
  const m = /[?&]secret=([A-Z2-7]+=*)/i.exec(uri);
  const label = decodeURIComponent((uri.split('otpauth://totp/')[1] || '').split('?')[0]);
  if (!m) throw new Error('QR sin parámetro secret');
  return { secret: m[1].toUpperCase(), label };
}
