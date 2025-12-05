// token.js
// -----------------------------------------------------------------------------
// Access / Refresh 토큰 발급 & 검증 + refresh_tokens 테이블 관리
// 현재 DB 스키마에 맞춰서 저장하도록 수정함
// -----------------------------------------------------------------------------

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { query } from './db.js';

// .env에서 값 읽기
const ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET ||
  process.env.ACCESS_SECRET ||
  'dev-access-secret';

const REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ||
  process.env.REFRESH_SECRET ||
  'dev-refresh-secret';

const ACCESS_TTL = process.env.ACCESS_TTL || '15m';
const REFRESH_TTL = process.env.REFRESH_TTL || '7d';

// sha256 해시 유틸
function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// 액세스 토큰 (짧게 사는 토큰)
export function signAccess(payload) {
  // payload 예: { sub: userId }
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
}

// 리프레시 토큰 (길게 사는 토큰)
export function signRefresh(payload) {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
}

// 액세스 토큰 검증
export function verifyAccess(token) {
  return jwt.verify(token, ACCESS_SECRET);
}

// 리프레시 토큰 검증
export function verifyRefresh(token) {
  return jwt.verify(token, REFRESH_SECRET);
}

// 리프레시 토큰을 DB(refresh_tokens 테이블)에 기록
// 현재 refresh_tokens 테이블 컬럼은 다음과 같다고 가정:
//   id (auto inc)
//   user_id varchar(36) NOT NULL
//   token_hash char(64) NOT NULL
//   user_agent varchar(255) NULL
//   ip varchar(64) NULL
//   issued_at datetime NOT NULL
//   expires_at datetime NOT NULL
//   revoked_at datetime NULL
export async function storeRefresh(userId, refreshToken, meta = {}) {
  const tokenHash = sha256(refreshToken);

  // refreshToken 안에 만료(exp: 초 단위 epoch)가 들어있음
  const decoded = jwt.decode(refreshToken);
  const expMs = decoded && decoded.exp
    ? decoded.exp * 1000
    : Date.now() + 7 * 24 * 3600 * 1000;

  const expiresAt = new Date(expMs); // JS Date -> mysql2가 DATETIME으로 넣어줌
  const issuedAt = new Date();       // 지금 발급 시각

  const ua = meta.userAgent || '';
  const ip = meta.ip || '';

  await query(
    `INSERT INTO refresh_tokens
       (user_id, token_hash, user_agent, ip, issued_at, expires_at, revoked_at)
     VALUES
       (?,       ?,         ?,          ?,  ?,         ?,          NULL)`,
    [userId, tokenHash, ua, ip, issuedAt, expiresAt]
  );
}

// 아직 유효한 refresh_token 인지 확인
// - revoked_at 이 NULL이어야 함
// - expires_at 이 현재 시각보다 미래여야 함
export async function isRefreshUsable(refreshToken) {
  const tokenHash = sha256(refreshToken);

  const row = await query(
    `SELECT
        user_id,
        token_hash,
        revoked_at,
        expires_at
     FROM refresh_tokens
     WHERE token_hash = ?
     LIMIT 1`,
    [tokenHash]
  ).then(r => r[0]?.[0] || null);

  if (!row) return false;
  if (row.revoked_at) return false;

  const now = Date.now();
  const expiresTime = new Date(row.expires_at).getTime();
  if (expiresTime <= now) return false;

  return true;
}

// refresh_token 폐기 (로그아웃)
export async function revokeRefresh(refreshToken) {
  const tokenHash = sha256(refreshToken);

  await query(
    `UPDATE refresh_tokens
     SET revoked_at = NOW()
     WHERE token_hash = ?`,
    [tokenHash]
  );
}
