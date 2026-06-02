# AI Code Security Reviewer Frontend

React dashboard for the MVP backend.

## Local Setup

```powershell
cp .env.example .env
npm install
npm run dev
```

The app expects the backend API at:

```env
VITE_API_BASE_URL=http://localhost:4000
VITE_CLERK_PUBLISHABLE_KEY=pk_test_...
```

Clerk provides the sign-in form, session handling, and user menu. Admin UI is shown when the signed-in Clerk user has public metadata:

```json
{
  "role": "admin"
}
```

Regular users see only their own scan history. Admin users get a separate Admin Dashboard tab with platform summary and audit log views.

Admin Dashboard includes:

- users management
- role changes between `user` and `admin`
- audit logs
- platform summary

Scan reports include an Export PDF action.

## MVP Screens

- ZIP upload
- GitHub repository submission
- Scan history
- Security report details
- Vulnerability list
- Security score
