<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Noto+Sans+KR&size=32&pause=1200&color=111111&center=true&vCenter=true&width=1000&lines=Daepang+Backend;Auth+%2F+Materials+%2F+AI+Quiz+API" alt="Daepang Backend Typing" />
</p>

<p align="center">
  <a href="https://github.com/ZonezIpex/Daepang-front"><img src="https://img.shields.io/badge/Frontend-Repo-181717?style=for-the-badge&logo=github&logoColor=white" /></a>
</p>

<br/>

## 📚 목차
1. [백엔드 역할](#1-백엔드-역할)  
2. [기술 스택](#2-기술-스택)  
3. [프로젝트 구조](#3-프로젝트-구조)  
4. [주요 API](#4-주요-api)  
5. [환경 변수](#5-환경-변수)  
6. [실행 방법](#6-실행-방법)

<br/>

## <a id="1-백엔드-역할"></a> 1. 백엔드 역할
- 회원가입/로그인 및 JWT 기반 인증 처리
- 학습 자료(Materials) CRUD + 파일 업로드/미리보기
- AI 퀴즈 생성 요청 및 결과 저장/조회
- MySQL 연동

<br/>

## <a id="2-기술-스택"></a> 2. 기술 스택
- Node.js
- Express
- mysql2
- jsonwebtoken (JWT)
- bcryptjs (비밀번호 해시)
- cors / cookie-parser
- dotenv
- OpenAI SDK

<br/>

## <a id="3-프로젝트-구조"></a> 3. 프로젝트 구조
현재 백엔드는 `daepang-auth-master/` 폴더에 구성되어 있습니다.

<pre>
Daepang-back
└─ daepang-auth-master
   ├─ server.js      # API 서버(라우팅/로직)
   ├─ db.js          # MySQL pool + query/ensureDB
   ├─ token.js       # access/refresh 발급/검증 + refresh_tokens 관리
   └─ package.json
</pre>

<br/>

## <a id="4-주요-api"></a> 4. 주요 API
아래는 `server.js` 기준으로 정리한 핵심 라우트입니다.

### Auth
- POST /api/auth/signup
- POST /api/auth/login
- POST /api/auth/logout
- GET  /api/auth/me

### Materials
- GET    /api/materials/public
- GET    /api/materials/mine
- GET    /api/materials/:id
- POST   /api/materials
- DELETE /api/materials/:id

### Files (Material Attachments)
- GET    /api/materials/:id/files
- POST   /api/materials/:id/files
- DELETE /api/materials/:mid/files/:fid
- GET    /api/materials/:mid/files/:fid/preview
- GET    /api/materials/:id/fulltext

### AI Quiz
- POST /api/ai/quiz
- GET  /api/materials/:id/ai/quiz-history
- GET  /api/ai/quiz/:rid

<br/>

## <a id="5-환경-변수"></a> 5. 환경 변수
`.env` 예시 (프로젝트 기준 키)

<pre>
# Server
PORT=8080
CORS_ORIGIN=http://localhost:3000

# DB (둘 중 하나 방식으로 입력)
MYSQL_HOST=127.0.0.1
MYSQL_USER=root
MYSQL_PASSWORD=****
MYSQL_DATABASE=daepang
MYSQL_PORT=3306

# JWT
JWT_ACCESS_SECRET=****
JWT_REFRESH_SECRET=****
ACCESS_TTL=15m
REFRESH_TTL=7d

# OpenAI
OPENAI_API_KEY=****
QUIZ_MODEL=gpt-4o-mini
</pre>
