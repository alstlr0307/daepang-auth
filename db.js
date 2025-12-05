// db.js
// MySQL 커넥션 풀 + 기본 유틸

import dotenv from "dotenv";
dotenv.config();

import mysql from "mysql2/promise";

// 환경변수 우선순위 정리
const host =
  process.env.MYSQL_HOST ??
  process.env.DB_HOST ??
  "127.0.0.1";

const user =
  process.env.MYSQL_USER ??
  process.env.DB_USER ??
  "root";

const password =
  process.env.MYSQL_PASSWORD ??
  process.env.DB_PASSWORD ??
  "";

const database =
  process.env.MYSQL_DATABASE ??
  process.env.DB_NAME ??
  "daepang";

const port = Number(
  process.env.MYSQL_PORT ??
    process.env.DB_PORT ??
    3306
);

const pool = mysql.createPool({
  host,
  user,
  password,
  database,
  port,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// 쿼리 helper
export async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// 서버 켜기 전에 연결 체크
export async function ensureDB() {
  try {
    const rows = await query("SELECT 1 AS ok");
    console.log(
      "[DB] connected:",
      host,
      database,
      "ok=",
      rows?.[0]?.ok
    );
  } catch (e) {
    console.error("[DB] connection failed:", e.message);
    throw e;
  }
}

export { pool };
