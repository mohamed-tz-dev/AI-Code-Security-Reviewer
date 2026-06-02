# AI Code Security Reviewer Backend

This backend is the MVP foundation for accepting repository scans, queueing scan work, storing scan history, and returning structured reports.

## Architecture

- `src/app.js` creates the Express app and mounts API routes.
- `src/server.js` starts the API after checking PostgreSQL connectivity.
- `src/db` owns PostgreSQL pooling and migrations.
- `src/queue` owns Redis and BullMQ setup.
- `src/modules/scans` owns scan API, persistence, and scan history.
- `src/modules/vulnerabilities` owns persistence for normalized security findings.
- `src/workers` contains background processors.
- `src/scanner` contains extraction, traversal, static analysis, and result aggregation.
The scanner performs deterministic static rule matching, AST-based code checks, secret detection, dependency review, and backend security analysis.

## Local Setup

1. Copy `.env.example` to `.env`.
2. Start PostgreSQL and Redis with Docker Compose.
3. Install dependencies.
4. Run migrations.
5. Start the API and worker.

```bash
cp .env.example .env
docker compose up -d
npm install
npm run migrate
npm run dev
npm run worker
```

## Clerk Auth

Authentication is controlled by these backend environment variables:

```env
CLERK_AUTH_ENABLED=true
CLERK_SECRET_KEY=sk_test_...
```

When auth is enabled, all scan API routes require a signed-in Clerk user. Admin access is based on Clerk user public metadata:

```json
{
  "role": "admin"
}
```

Users without that metadata are treated as regular users and can only see their own scans.

Data access rule:

- Regular users only see scans where `scans.user_id` matches their Clerk user id.
- Admin users can see every scan.
- Legacy scans with no `user_id` are admin-visible only.

Audit log:

- `scan.created`
- `scan.started`
- `scan.completed`
- `scan.failed`

Admins can read audit events from `GET /api/admin/audit-logs`.

Admin users management:

- `GET /api/admin/users`
- `PATCH /api/admin/users/:userId/role`

Scan PDF export:

- `GET /api/scans/:scanId/export.pdf`

Users can export their own scan reports. Admins can export any scan report.

## Scanner Methods

The scanner combines:

- static rule matching
- JavaScript/TypeScript AST rules through `@babel/parser`
- Python AST rules through Python's standard-library `ast` parser
- local RAG security knowledge retrieval for AI prompts
- optional AI review through OpenAI, Ollama, or GroqCloud

If AST analysis logs that the parser is missing, run:

```powershell
npm install
```

Python AST support requires Python on PATH:

```powershell
python --version
```

Docker Compose exposes this project's PostgreSQL on host port `55432` to avoid conflicts with an existing local PostgreSQL server on `5432`.

Docker Compose exposes this project's Redis on host port `6380`. If you already have Redis running on `6379`, either keep `REDIS_URL=redis://localhost:6379` or switch it to `redis://localhost:6380` after starting the Compose Redis container.

For Ollama-based AI analysis, install/pull the model locally and keep Ollama running:

```powershell
ollama pull deepseek-coder:6.7b
```

For GroqCloud-based AI analysis, set `AI_PROVIDER=groq` and `GROQ_CLOUD_API_KEY` in your `.env` file.

On Windows, if Docker tries to read a locked user config file, use the helper script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-local.ps1
```

If you already have PostgreSQL installed locally and want to use it instead, update `DATABASE_URL` in `.env` with the correct username, password, host, port, and database name before running migrations.

## API Endpoints

- `GET /health`
- `GET /api/scans`
- `GET /api/scans/:scanId`
- `POST /api/scans/zip` with multipart field `repository`
- `POST /api/scans/github` with JSON body `{ "repositoryUrl": "https://github.com/org/repo" }`
  - Optional: include `"githubAccessToken": "<token>"` to import private repos using GitHub OAuth/PAT credentials.

## CI/CD Integration Templates

Example templates for triggering repository scans from CI/CD pipelines are available in `backend/ci-templates`:

- `github-actions-security-scan.yml`
- `gitlab-ci.yml`
- `jenkins-pipeline.groovy`

Each template sends a `POST` request to `$SECURITY_REVIEW_API_URL/api/scans/github` using the configured `SECURITY_REVIEW_API_TOKEN`.

## Security Baseline

- Uploaded code is stored and scanned as data only.
- The backend never executes repository files.
- SQL uses parameterized queries.
- Large uploads are capped by `MAX_UPLOAD_MB`.
- Scan jobs run asynchronously through BullMQ.
