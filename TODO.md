# TODO - Clerk Modern Auth Fixes

- [x] Add backend endpoint `POST /api/auth/clerk` that verifies Clerk token, resolves email, find-or-create user, and issues app JWT.
- [x] Wire backend route in `backend/src/modules/auth/auth.routes.js`.
- [x] Update frontend redirect exchange to call `/api/auth/clerk` instead of `/api/auth/google`.
- [x] Ensure backward compatibility: keep `/api/auth/google` as alias to Clerk auth.
- [x] Run backend tests.

