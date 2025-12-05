// server.js
// Express + MySQL + JWT + 파일 업로드 + CORS + OpenAI 연동 (대팡 프로젝트)
//
// 제공 기능:
// - JWT 로그인/회원가입
// - 자료 CRUD + 파일 업로드
// - AI 도우미: 노트(또는 임시 텍스트) → 퀴즈 생성
// - 퀴즈 히스토리 (내가 만든 거만)
//
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import OpenAI from "openai";
import { fileURLToPath } from "url";
import { ensureDB, query } from "./db.js";

// -----------------------------------------------------------------------------
// 초기화 (.env 로드)
// -----------------------------------------------------------------------------
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -----------------------------------------------------------------------------
// 환경 상수
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 4000;

const ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET ||
  process.env.ACCESS_SECRET ||
  "dev-access-secret";

const ACCESS_TTL = process.env.ACCESS_TTL || "7d";

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const QUIZ_MODEL = process.env.QUIZ_MODEL || "gpt-4o-mini";

// 업로드 디렉토리
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// OpenAI 클라이언트
const openai = new OpenAI({
  apiKey: OPENAI_API_KEY,
});

// -----------------------------------------------------------------------------
// CORS 설정
// -----------------------------------------------------------------------------
function normalizeOrigin(o) {
  if (!o) return "";
  return o.replace(/\/+$/, "");
}
const NGROK_RE = /^https:\/\/[a-z0-9-]+\.ngrok-free\.dev$/i;
const ENV_ORIGINS = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => normalizeOrigin(s.trim()))
  .filter(Boolean);

const corsOptions = {
  origin(origin, cb) {
    const o = normalizeOrigin(origin);

    // 브라우저 아닌 비동기 툴/curl 등은 origin이 빈 경우도 있으니 허용
    if (!o) return cb(null, true);

    if (o === "http://localhost:3000") return cb(null, true);
    if (o === "http://localhost:4000") return cb(null, true);
    if (ENV_ORIGINS.includes(o)) return cb(null, true);
    if (NGROK_RE.test(o)) return cb(null, true);

    console.warn("[CORS BLOCKED ORIGIN]", origin);
    return cb(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Filename"],
};

// -----------------------------------------------------------------------------
// JWT 헬퍼
// -----------------------------------------------------------------------------
function signAccessToken(userId) {
  return jwt.sign({ sub: userId }, ACCESS_SECRET, {
    expiresIn: ACCESS_TTL,
  });
}

function parseAuthHeader(req) {
  const h = req.headers["authorization"];
  if (!h) return null;
  const [scheme, token] = h.split(" ");
  if (scheme !== "Bearer" || !token) return null;
  try {
    const decoded = jwt.verify(token, ACCESS_SECRET);
    return decoded; // { sub, iat, exp }
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const payload = parseAuthHeader(req);
  if (!payload) {
    return res.status(401).json({ error: "unauthorized" });
  }
  req.userId = payload.sub;
  next();
}

// -----------------------------------------------------------------------------
// APP 미들웨어
// -----------------------------------------------------------------------------
const app = express();

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// -----------------------------------------------------------------------------
// 유틸
// -----------------------------------------------------------------------------
function normalizeLimit(v, def = 20, max = 50) {
  let n = parseInt(v, 10);
  if (Number.isNaN(n) || n < 1) n = def;
  if (n > max) n = max;
  return n;
}

// -----------------------------------------------------------------------------
// DB helper
// -----------------------------------------------------------------------------

// 로그인 후 프론트에 내려줄 "안전한" 유저 정보
async function getUserById(uid) {
  const rows = await query(
    `
    SELECT
      id,
      email,
      display_name AS displayName,
      role
    FROM users
    WHERE id = ?
    LIMIT 1
    `,
    [uid]
  );
  return rows[0] || null;
}

// 로그인용 (비번 포함)
async function getUserAuthByEmail(email) {
  const rows = await query(
    `
    SELECT
      id,
      email,
      display_name AS displayName,
      role,
      password_hash
    FROM users
    WHERE email = ?
    LIMIT 1
    `,
    [email]
  );
  return rows[0] || null;
}

// 회원가입
async function createUserWithPassword(email, displayName, rawPassword) {
  const newId = crypto.randomUUID();
  const hash = bcrypt.hashSync(rawPassword, 10);

  await query(
    `
    INSERT INTO users (id, email, display_name, password_hash, role)
    VALUES (?, ?, ?, ?, 'user')
    `,
    [newId, email, displayName, hash]
  );

  return getUserById(newId);
}

// material row -> 프론트 friendly
function mapMaterialRow(r) {
  return {
    id: r.id,
    owner_id: r.user_uuid,
    title: r.title,
    description: r.description ?? null,
    privacy: r.privacy,
    license: r.license ?? null,
    created_at: r.created_at ?? null,
  };
}

// 권한 체크
function canReadMaterial(viewerId, matRow) {
  if (!matRow) return false;
  if (matRow.privacy === "public" || matRow.privacy === "unlisted") {
    return true;
  }
  if (viewerId && String(viewerId) === String(matRow.user_uuid)) {
    return true;
  }
  return false;
}

function canWriteMaterial(viewerId, matRow) {
  if (!matRow) return false;
  return viewerId && String(viewerId) === String(matRow.user_uuid);
}

// 내가 올린 자료 목록
async function fetchMyMaterials(uid, limit) {
  const safeLimit = Number(limit) || 20;

  // LIMIT 은 바인딩 불가라 문자열에 직접 삽입 (safeLimit은 이미 숫자화)
  const sql = `
    SELECT
      id,
      user_uuid,
      title,
      description,
      privacy,
      license,
      created_at,
      status
    FROM materials
    WHERE user_uuid = ?
    ORDER BY created_at DESC
    LIMIT ${safeLimit}
  `;

  const rows = await query(sql, [uid]);
  return rows;
}

// 공개 자료 목록
async function fetchPublicMaterials(limit) {
  const safeLimit = Number(limit) || 20;

  const sql = `
    SELECT
      id,
      user_uuid,
      title,
      description,
      privacy,
      license,
      created_at,
      status
    FROM materials
    WHERE privacy IN ('public','unlisted')
      AND status = 'ready'
    ORDER BY created_at DESC
    LIMIT ${safeLimit}
  `;

  const rows = await query(sql, []);
  return rows;
}

// 단일 자료
async function fetchOneMaterial(matId) {
  const rows = await query(
    `
    SELECT
      id,
      user_uuid,
      title,
      description,
      privacy,
      license,
      created_at,
      status
    FROM materials
    WHERE id = ?
    LIMIT 1
    `,
    [matId]
  );
  return rows[0] || null;
}

// -----------------------------------------------------------------------------
// AI 도우미용 헬퍼
// -----------------------------------------------------------------------------

// (1) 특정 자료의 전체 텍스트(본문 + 첨부 텍스트 파일 내용들) 합치기
async function buildMaterialFullText(materialId) {
  const mat = await fetchOneMaterial(materialId);
  if (!mat) return null;

  const files = await query(
    `
    SELECT
      id,
      file_key,
      file_ext,
      orig_name
    FROM material_files
    WHERE material_id = ?
    ORDER BY id ASC
    `,
    [materialId]
  );

  const parts = [];

  // 본문
  if (mat.description) {
    parts.push("### 본문\n" + mat.description + "\n");
  }

  // 첨부 파일
  for (const f of files) {
    const ext = (f.file_ext || "").toLowerCase();
    const filePath = path.join(UPLOAD_DIR, f.file_key);

    if (!fs.existsSync(filePath)) {
      continue;
    }

    const textExts = [
      "txt",
      "md",
      "markdown",
      "json",
      "csv",
      "log",
      "js",
      "ts",
      "tsx",
      "java",
      "py",
      "c",
      "cpp",
      "cs",
      "html",
      "css",
      "sql",
    ];

    if (textExts.includes(ext)) {
      try {
        const textContent = fs.readFileSync(filePath, "utf8");
        parts.push(`\n### 파일: ${f.orig_name}\n` + textContent + "\n");
      } catch {
        parts.push(
          `\n### 파일: ${f.orig_name}\n(텍스트 읽기 실패)\n`
        );
      }
    } else {
      parts.push(
        `\n### 파일: ${f.orig_name}\n(이미지/비텍스트 파일 - 내용은 미포함)\n`
      );
    }
  }

  return {
    materialId,
    ownerId: mat.user_uuid,
    title: mat.title,
    text: parts.join("\n").trim(),
  };
}

// (2) LLM 호출로 퀴즈 생성 (안되면 fallback)
async function generateQuizFromText(fullText, count) {
  const safeCount = Math.max(1, Number(count) || 5);

  // 너무 긴 텍스트는 잘라서 모델에 보냄
  const MAX_CHARS = 8000;
  const clipped = fullText.slice(0, MAX_CHARS);

  const systemPrompt = [
    "너는 공부용 문제은행 생성기 역할을 하는 튜터야.",
    "입력된 학습자료를 읽고 중요한 개념을 묻는 객관식 문제를 만들어.",
    "각 문제는 반드시 하나의 정답만 있어야 하고 나머지는 헷갈리는 오답이면 좋아.",
    "정답 인덱스(answerIndex)는 0부터 시작해.",
    "출력은 반드시 아래 JSON 스키마를 지켜.",
    "",
    "{",
    '  "questions": [',
    "    {",
    '      "type": "mcq",',
    '      "question": "문자열",',
    '      "choices": ["선지1", "선지2", "선지3", "선지4"],',
    '      "answerIndex": 0,',
    '      "explanation": "정답 해설 (선택)"',
    "    }",
    "  ]",
    "}",
  ].join("\n");

  const userPrompt = [
    `아래 학습자료를 바탕으로 ${safeCount}개의 객관식 문제를 만들어줘.`,
    "",
    "=== 학습자료 시작 ===",
    clipped,
    "=== 학습자료 끝 ===",
  ].join("\n");

  // OpenAI 호출 시도
  if (OPENAI_API_KEY) {
    try {
      const completion = await openai.chat.completions.create({
        model: QUIZ_MODEL,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
      });

      const raw = completion.choices?.[0]?.message?.content || "{}";
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        console.warn("[AI QUIZ] JSON.parse 실패, raw=", raw, e);
      }

      if (
        parsed &&
        Array.isArray(parsed.questions) &&
        parsed.questions.length > 0
      ) {
        return {
          questions: parsed.questions.map((q, i) => ({
            type: "mcq",
            question:
              typeof q.question === "string"
                ? q.question
                : `문제 ${i + 1}`,
            choices: Array.isArray(q.choices) ? q.choices : [],
            answerIndex:
              typeof q.answerIndex === "number" ? q.answerIndex : 0,
            explanation:
              typeof q.explanation === "string" ? q.explanation : "",
          })),
        };
      } else {
        console.warn("[AI QUIZ] parsed 구조 이상, fallback 사용");
      }
    } catch (err) {
      console.error("[AI QUIZ] OpenAI 호출 실패", err);
    }
  } else {
    console.warn("[AI QUIZ] OPENAI_API_KEY 없음 -> fallback 사용");
  }

  // fallback 더미 데이터
  const fallbackQs = [];
  for (let i = 0; i < safeCount; i++) {
    fallbackQs.push({
      type: "mcq",
      question: `이 문서의 핵심 개념 ${i + 1}은 무엇입니까?`,
      choices: [
        "개념 A (임시)",
        "개념 B (임시)",
        "개념 C (임시)",
        "개념 D (임시)",
      ],
      answerIndex: 0,
      explanation: "임시 데이터 (AI 미연결 또는 실패)",
    });
  }

  return { questions: fallbackQs };
}

// (3) material 기반 퀴즈 결과 DB 저장
async function saveAIResult({
  materialId,
  userId,
  mode,
  questionCount,
  resultObject,
}) {
  const jsonStr = JSON.stringify(resultObject);

  const r = await query(
    `
    INSERT INTO ai_results
      (material_id, user_uuid, mode, question_count, result_json, created_at)
    VALUES (?, ?, ?, ?, ?, NOW())
    `,
    [materialId, userId, mode, questionCount ?? null, jsonStr]
  );

  return r.insertId;
}

// -----------------------------------------------------------------------------
// AUTH 라우트
// -----------------------------------------------------------------------------

// 회원가입
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password, displayName } = req.body || {};
    if (!email || !password || !displayName) {
      return res.status(400).json({ error: "missing_fields" });
    }

    const exists = await getUserAuthByEmail(email);
    if (exists) {
      return res.status(409).json({ error: "email_taken" });
    }

    await createUserWithPassword(email, displayName, password);
    res.json({ ok: true });
  } catch (e) {
    console.error("POST /api/auth/signup error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// 로그인
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "missing_fields" });
    }

    const u = await getUserAuthByEmail(email);
    if (!u) {
      return res.status(401).json({ error: "invalid_login" });
    }

    const ok = bcrypt.compareSync(password, u.password_hash || "");
    if (!ok) {
      return res.status(401).json({ error: "invalid_login" });
    }

    const token = signAccessToken(u.id);

    const safeUser = {
      id: u.id,
      email: u.email,
      displayName: u.displayName,
      role: u.role,
    };

    res.json({
      accessToken: token,
      user: safeUser,
    });
  } catch (e) {
    console.error("POST /api/auth/login error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// 로그아웃 (토큰 블랙리스트는 안 쓰는 간단 버전)
app.post("/api/auth/logout", requireAuth, async (_req, res) => {
  res.status(204).end();
});

// 내 정보
app.get("/api/auth/me", async (req, res) => {
  try {
    const payload = parseAuthHeader(req);
    if (!payload) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const u = await getUserById(payload.sub);
    if (!u) {
      return res.status(401).json({ error: "unauthorized" });
    }

    res.json(u);
  } catch (e) {
    console.error("GET /api/auth/me error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// -----------------------------------------------------------------------------
// MATERIALS 라우트
// -----------------------------------------------------------------------------

// 공개 자료 리스트
app.get("/api/materials/public", async (req, res) => {
  const limit = normalizeLimit(req.query.limit);
  try {
    const rows = await fetchPublicMaterials(limit);
    const items = rows.map(mapMaterialRow);

    res.json({
      items,
      nextCursor: null,
    });
  } catch (e) {
    console.error("GET /api/materials/public error", e);
    res.json({ items: [], nextCursor: null });
  }
});

// 내 자료 리스트
app.get("/api/materials/mine", requireAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const limit = normalizeLimit(req.query.limit);

    const rows = await fetchMyMaterials(uid, limit);
    const items = rows.map(mapMaterialRow);

    res.json({
      items,
      nextCursor: null,
    });
  } catch (e) {
    console.error("GET /api/materials/mine error", e);
    res.json({ items: [], nextCursor: null });
  }
});

// 단일 자료 (상세)
app.get("/api/materials/:id", async (req, res) => {
  try {
    const matId = Number(req.params.id);
    if (!matId) {
      return res.status(400).json({ error: "invalid id" });
    }

    const mat = await fetchOneMaterial(matId);
    if (!mat) {
      return res.status(404).json({ error: "not found" });
    }

    const payload = parseAuthHeader(req);
    if (!canReadMaterial(payload?.sub, mat)) {
      return res.status(403).json({ error: "forbidden" });
    }

    res.json(mapMaterialRow(mat));
  } catch (e) {
    console.error("GET /api/materials/:id error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// 새 자료
app.post("/api/materials", requireAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const { title, privacy, license, description } = req.body || {};

    if (!title) {
      return res.status(400).json({ error: "title required" });
    }

    const p = privacy || "private";

    const result = await query(
      `
      INSERT INTO materials
        (user_uuid, title, description, privacy, license, status, created_at)
      VALUES
        (?,        ?,     ?,           ?,       ?,       'ready', NOW())
      `,
      [uid, title, description ?? null, p, license ?? null]
    );

    const newId = result.insertId;
    res.json({ id: newId });
  } catch (e) {
    console.error("POST /api/materials error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// 수정 (privacy/description 등)
app.patch("/api/materials/:id", requireAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const matId = Number(req.params.id);

    const matBefore = await fetchOneMaterial(matId);
    if (!matBefore) {
      return res.status(404).json({ error: "not found" });
    }
    if (!canWriteMaterial(uid, matBefore)) {
      return res.status(403).json({ error: "forbidden" });
    }

    const patch = req.body || {};
    const newPrivacy = patch.privacy ?? matBefore.privacy;
    const newLicense = patch.license ?? matBefore.license;
    const newDesc = patch.description ?? matBefore.description;

    await query(
      `
      UPDATE materials
      SET privacy = ?, license = ?, description = ?
      WHERE id = ?
      `,
      [newPrivacy, newLicense, newDesc, matId]
    );

    const updated = await fetchOneMaterial(matId);
    res.json(mapMaterialRow(updated));
  } catch (e) {
    console.error("PATCH /api/materials/:id error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// 삭제 (파일까지 같이)
app.delete("/api/materials/:id", requireAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const matId = Number(req.params.id);

    const mat = await fetchOneMaterial(matId);
    if (!mat) {
      return res.status(404).json({ error: "not found" });
    }
    if (!canWriteMaterial(uid, mat)) {
      return res.status(403).json({ error: "forbidden" });
    }

    // 연결된 파일들 찾아서 실제 파일도 지움
    const files = await query(
      `
      SELECT *
      FROM material_files
      WHERE material_id = ?
      `,
      [matId]
    );

    for (const f of files) {
      const filePath = path.join(UPLOAD_DIR, f.file_key);
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch {
          /* ignore */
        }
      }
    }

    await query(
      `DELETE FROM material_files WHERE material_id = ?`,
      [matId]
    );
    await query(`DELETE FROM materials WHERE id = ?`, [matId]);

    res.json({ ok: true });
  } catch (e) {
    console.error("DELETE /api/materials/:id error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// 파일 목록
app.get("/api/materials/:id/files", async (req, res) => {
  try {
    const matId = Number(req.params.id);
    if (!matId) {
      return res.status(400).json({ error: "invalid id" });
    }

    const mat = await fetchOneMaterial(matId);
    if (!mat) return res.status(404).json({ error: "not found" });

    const payload = parseAuthHeader(req);
    if (!canReadMaterial(payload?.sub, mat)) {
      return res.status(403).json({ error: "forbidden" });
    }

    const rows = await query(
      `
      SELECT
        id,
        orig_name,
        file_ext,
        bytes
      FROM material_files
      WHERE material_id = ?
      ORDER BY id DESC
      `,
      [matId]
    );

    const items = rows.map((f) => ({
      id: String(f.id),
      name: f.orig_name,
      ext: f.file_ext,
      bytes: f.bytes,
    }));

    res.json({ items });
  } catch (e) {
    console.error("GET /api/materials/:id/files error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// 파일 업로드
app.post(
  "/api/materials/:id/files",
  requireAuth,
  express.raw({
    type: "application/octet-stream",
    limit: "20mb",
  }),
  async (req, res) => {
    try {
      const uid = req.userId;
      const matId = Number(req.params.id);
      const origName = req.header("X-Filename") || "file.bin";

      const mat = await fetchOneMaterial(matId);
      if (!mat) return res.status(404).json({ error: "not found" });
      if (!canWriteMaterial(uid, mat)) {
        return res.status(403).json({ error: "forbidden" });
      }

      const buf = req.body || Buffer.alloc(0);
      const sha256 = crypto.createHash("sha256").update(buf).digest("hex");

      const ext = path
        .extname(origName || "")
        .replace(/^\./, "")
        .toLowerCase();

      const fileKey =
        Date.now().toString() +
        "_" +
        crypto.randomUUID() +
        (ext ? "." + ext : "");

      const absPath = path.join(UPLOAD_DIR, fileKey);
      fs.writeFileSync(absPath, buf);

      const r = await query(
        `
        INSERT INTO material_files
          (material_id, file_key, file_ext, bytes, sha256, orig_name)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [matId, fileKey, ext || null, buf.length, sha256, origName]
      );

      const fileId = r.insertId;

      res.json({
        id: fileId,
        file_key: fileKey,
        file_ext: ext,
        bytes: buf.length,
        sha256,
        orig_name: origName,
      });
    } catch (e) {
      console.error("POST /api/materials/:id/files error", e);
      res.status(500).json({ error: "server_error" });
    }
  }
);

// 파일 삭제
app.delete(
  "/api/materials/:mid/files/:fid",
  requireAuth,
  async (req, res) => {
    try {
      const uid = req.userId;
      const mid = Number(req.params.mid);
      const fid = Number(req.params.fid);

      const mat = await fetchOneMaterial(mid);
      if (!mat) return res.status(404).json({ error: "not found" });
      if (!canWriteMaterial(uid, mat)) {
        return res.status(403).json({ error: "forbidden" });
      }

      const rows = await query(
        `
        SELECT *
        FROM material_files
        WHERE id = ?
          AND material_id = ?
        LIMIT 1
        `,
        [fid, mid]
      );
      const f = rows[0];
      if (!f) {
        return res.status(404).json({ error: "file not found" });
      }

      const filePath = path.join(UPLOAD_DIR, f.file_key);
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch {
          /* ignore */
        }
      }

      await query(
        `
        DELETE FROM material_files
        WHERE id = ?
          AND material_id = ?
        `,
        [fid, mid]
      );

      res.json({ ok: true });
    } catch (e) {
      console.error("DELETE /api/materials/:mid/files/:fid error", e);
      res.status(500).json({ error: "server_error" });
    }
  }
);

// 파일 미리보기
app.get("/api/materials/:mid/files/:fid/preview", async (req, res) => {
  try {
    const mid = Number(req.params.mid);
    const fid = Number(req.params.fid);

    const mat = await fetchOneMaterial(mid);
    if (!mat) return res.status(404).json({ error: "not found" });

    const payload = parseAuthHeader(req);
    if (!canReadMaterial(payload?.sub, mat)) {
      return res.status(403).json({ error: "forbidden" });
    }

    const rows = await query(
      `
      SELECT *
      FROM material_files
      WHERE id = ?
        AND material_id = ?
      LIMIT 1
      `,
      [fid, mid]
    );
    const f = rows[0];
    if (!f) {
      return res.status(404).json({ error: "file not found" });
    }

    const filePath = path.join(UPLOAD_DIR, f.file_key);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "missing file" });
    }

    const ext = (f.file_ext || "").toLowerCase().trim();
    const imageExts = ["png", "jpg", "jpeg", "gif", "webp"];
    const textExts = ["txt", "md", "markdown", "json", "csv"];

    if (imageExts.includes(ext)) {
      const mime =
        ext === "jpg" || ext === "jpeg"
          ? "image/jpeg"
          : ext === "png"
          ? "image/png"
          : ext === "gif"
          ? "image/gif"
          : ext === "webp"
          ? "image/webp"
          : "application/octet-stream";

      res.setHeader("Content-Type", mime);
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    if (textExts.includes(ext)) {
      const text = fs.readFileSync(filePath, "utf8");
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.send(text);
      return;
    }

    res.setHeader("Content-Type", "application/octet-stream");
    fs.createReadStream(filePath).pipe(res);
  } catch (e) {
    console.error("GET preview error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// -----------------------------------------------------------------------------
// AI 도우미 라우트
// -----------------------------------------------------------------------------

// (A) 특정 자료 전체 텍스트를 통으로 리턴
//     -> 워크벤치에서 그대로 textarea 초기값에 써도 되고, 디버깅용
app.get("/api/materials/:id/fulltext", async (req, res) => {
  try {
    const matId = Number(req.params.id);
    if (!matId) {
      return res.status(400).json({ error: "invalid id" });
    }

    const mat = await fetchOneMaterial(matId);
    if (!mat) {
      return res.status(404).json({ error: "not found" });
    }

    const payload = parseAuthHeader(req);

    // *** 디버그 로그: 실제 서버 콘솔에 찍힘
    console.log("[FULLTEXT access check]", {
      matId,
      matPrivacy: mat.privacy,
      owner: mat.user_uuid,
      viewer: payload?.sub || null,
    });

    if (!canReadMaterial(payload?.sub, mat)) {
      console.warn("[FULLTEXT forbidden]", { matId });
      return res.status(403).json({ error: "forbidden" });
    }

    const built = await buildMaterialFullText(matId);
    if (!built) {
      return res.status(500).json({ error: "build_failed" });
    }

    res.json({
      materialId: built.materialId,
      title: built.title,
      text: built.text,
    });
  } catch (e) {
    console.error("GET /api/materials/:id/fulltext error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// (B) 퀴즈 생성
// body: {
//   mode: "adhoc" | "material",
//   text?: string,        // adhoc일 때
//   materialId?: number,  // material일 때
//   count: number
// }
app.post("/api/ai/quiz", requireAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const { mode, text, materialId, count } = req.body || {};

    // adhoc 모드: 그냥 사용자가 textarea에 넣은 텍스트 기반
    if (mode === "adhoc") {
      if (!text || !String(text).trim()) {
        return res
          .status(400)
          .json({ error: "text_required_for_adhoc" });
      }

      // 퀴즈 생성
      const quizObj = await generateQuizFromText(String(text), count || 5);

      const questionCount = Array.isArray(quizObj.questions)
        ? quizObj.questions.length
        : 0;

      // adhoc은 DB 히스토리 X (ai_results에 안 넣음)
      return res.json({
        id: null,
        materialId: null,
        mode: "adhoc",
        questionCount,
        createdAt: new Date().toISOString(),
        data: quizObj,
      });
    }

    // material 모드: 특정 자료 기반 (본문 + 첨부 텍스트)
    if (mode === "material") {
      const matIdNum = Number(materialId);
      if (!matIdNum) {
        return res
          .status(400)
          .json({ error: "invalid_material_id" });
      }

      const mat = await fetchOneMaterial(matIdNum);
      if (!mat) {
        return res.status(404).json({ error: "not_found" });
      }
      // 읽기권한(공개 or 내 소유) 체크
      if (!canReadMaterial(uid, mat)) {
        return res.status(403).json({ error: "forbidden" });
      }

      // 전체 텍스트 구성
      const built = await buildMaterialFullText(matIdNum);
      if (!built) {
        return res.status(500).json({ error: "build_failed" });
      }

      // 실제 퀴즈 생성
      const quizObj = await generateQuizFromText(
        built.text,
        count || 5
      );

      const questionCount = Array.isArray(quizObj.questions)
        ? quizObj.questions.length
        : 0;

      // DB 저장 (여긴 히스토리로 쓰고 싶으니까 저장)
      // mode='quiz' 로 저장해서 quiz-history랑 맞춰준다
      const newResultId = await saveAIResult({
        materialId: matIdNum,
        userId: uid,
        mode: "quiz",
        questionCount,
        resultObject: quizObj,
      });

      return res.json({
        id: newResultId,
        materialId: matIdNum,
        mode: "quiz",
        questionCount,
        createdAt: new Date().toISOString(),
        data: quizObj,
      });
    }

    // mode가 둘 중 하나도 아니면
    return res.status(400).json({ error: "invalid_mode" });
  } catch (e) {
    console.error("POST /api/ai/quiz error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// (C) 특정 자료에 대해 "내가 만든 퀴즈들" 히스토리
app.get(
  "/api/materials/:id/ai/quiz-history",
  requireAuth,
  async (req, res) => {
    try {
      const uid = req.userId;
      const matId = Number(req.params.id);
      if (!matId) {
        return res.status(400).json({ error: "invalid id" });
      }

      const mat = await fetchOneMaterial(matId);
      if (!mat) {
        return res.status(404).json({ error: "not found" });
      }
      if (!canReadMaterial(uid, mat)) {
        return res.status(403).json({ error: "forbidden" });
      }

      const rows = await query(
        `
        SELECT
          id,
          question_count,
          created_at
        FROM ai_results
        WHERE material_id = ?
          AND user_uuid = ?
          AND mode = 'quiz'
        ORDER BY id DESC
        `,
        [matId, uid]
      );

      const items = rows.map((r) => ({
        id: r.id,
        questionCount: r.question_count,
        createdAt: r.created_at,
      }));

      res.json({ items });
    } catch (e) {
      console.error(
        "GET /api/materials/:id/ai/quiz-history error",
        e
      );
      res.status(500).json({ error: "server_error" });
    }
  }
);

// (D) 옛날에 만든 퀴즈 하나 다시 불러오기
app.get("/api/ai/quiz/:rid", requireAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const rid = Number(req.params.rid);
    if (!rid) {
      return res.status(400).json({ error: "invalid id" });
    }

    const rows = await query(
      `
      SELECT
        id,
        material_id,
        mode,
        question_count,
        result_json,
        created_at
      FROM ai_results
      WHERE id = ?
        AND user_uuid = ?
      LIMIT 1
      `,
      [rid, uid]
    );

    const row = rows[0];
    if (!row) {
      return res.status(404).json({ error: "not found" });
    }

    let data = null;
    try {
      data = JSON.parse(row.result_json);
    } catch {
      data = null;
    }

    res.json({
      id: row.id,
      materialId: row.material_id,
      mode: row.mode,
      questionCount: row.question_count,
      createdAt: row.created_at,
      data,
    });
  } catch (e) {
    console.error("GET /api/ai/quiz/:rid error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// -----------------------------------------------------------------------------
// 디버그 라우트
// -----------------------------------------------------------------------------
app.get("/api/debug/materials", async (_req, res) => {
  const rows = await query(
    `
    SELECT id, user_uuid, title, privacy, status, created_at
    FROM materials
    ORDER BY created_at DESC
    LIMIT 50
    `
  );
  res.json({ rows });
});

app.get("/favicon.ico", (_req, res) => res.status(204).end());
app.get("/manifest.json", (_req, res) => res.status(204).end());
app.get("/logo192.png", (_req, res) => res.status(204).end());

// -----------------------------------------------------------------------------
// 서버 시작
// -----------------------------------------------------------------------------
await ensureDB();

app.listen(PORT, () => {
  console.log("listening on", PORT);
  console.log(
    "CORS allowed origins:",
    [
      "http://localhost:3000",
      "http://localhost:4000",
      ...ENV_ORIGINS,
      "*.ngrok-free.dev",
    ].join(", ")
  );
});
