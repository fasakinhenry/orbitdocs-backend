# OrbitDocs backend

Node, Express, TypeScript, MongoDB (Mongoose), any S3 compatible storage (Backblaze B2, AWS S3, Cloudflare R2, Wasabi, MinIO).

## Storage

Files live in any S3 compatible bucket. Set `STORAGE_PROVIDER` and the matching values in `.env`.

- **Backblaze B2** (free 10 GB, no card needed to start): create a private bucket, create an application key limited to that bucket, set `STORAGE_PROVIDER=b2`, `STORAGE_REGION` (for example `us-west-004`), the key ID and key, and the bucket name.
- **AWS S3**: `STORAGE_PROVIDER=s3` with `STORAGE_REGION`.
- **Cloudflare R2**: `STORAGE_PROVIDER=r2` with `STORAGE_ENDPOINT=https://ACCOUNT_ID.r2.cloudflarestorage.com`.
- **Anything else S3 compatible** (Wasabi, MinIO, Spaces): `STORAGE_PROVIDER=custom` with `STORAGE_ENDPOINT`.

Switching provider later is an env change. Existing files do not move automatically, so copy the bucket contents first.

## Cost protection

Every workspace has a storage quota (default 200 MB), uploads are capped per file (default 25 MB), and trashed files still count until deleted forever. The platform admin can change the defaults, set a custom quota per workspace, suspend workspaces or users, and close sign ups from the admin dashboard.

## Platform admin

Only the account registered with `ADMIN_EMAIL` (and with that email verified) can use `/api/admin/*` and the `/admin` page. Everyone else gets a 404.

## Run it

```bash
bun install
cp .env.example .env   # fill in every value
bun run dev
```

The API starts on `PORT` (default 5000). Check `GET /health`.

## Deploy to Render

Build command: `npm install && npm run build`. Start command: `npm start`. Create a Resend API key and verify your sending domain first. Add every variable from `.env.example` in the Render dashboard, and set `CLIENT_URL` to your Vercel URL. In MongoDB Atlas, allow Render's outbound IPs.

## Roles

`owner` > `admin` > `member`. Members can view, search, upload, star, and download. Admins can also create folders, trash, restore, delete forever, approve, set the logo, and read activity. Non-members get a 404 for any organization route.

## Endpoints (all under /api)

| Method | Path | Role |
| --- | --- | --- |
| POST | /auth/register, /auth/login, /auth/refresh, /auth/logout | public |
| GET | /auth/me | signed in |
| POST | /auth/verify/send | signed in |
| POST | /auth/verify, /auth/forgot, /auth/reset | public |
| POST | /orgs | signed in |
| PATCH | /orgs/:orgId | admin |
| POST | /orgs/:orgId/logo | admin |
| GET | /orgs/:orgId/notifications | member |
| POST | /orgs/:orgId/notifications/read | member |
| GET, POST | /orgs/:orgId/folders | member, admin |
| GET | /orgs/:orgId/documents?view&folder&q&sort&dir&page&limit | member |
| POST | /orgs/:orgId/documents (multipart: files, folderId) | member |
| POST | /orgs/:orgId/documents/star | member |
| POST | /orgs/:orgId/documents/submit | member (own drafts only) |
| POST | /orgs/:orgId/documents/trash, /restore, /status | admin |
| DELETE | /orgs/:orgId/documents | admin |
| GET | /orgs/:orgId/documents/:id/download (add ?inline=1 for preview) | member |
| GET | /orgs/:orgId/activity | admin |
| GET | /auth/username/:name | public (availability check) |
| GET | /orgs/:orgId/usage | member |
| GET, POST, DELETE | /orgs/:orgId/links, /orgs/:orgId/links/:id | admin (shareable join links) |
| GET | /invites/mine | signed in |
| POST | /invites/mine/:id/accept | signed in |
| GET, POST | /join/:token | public preview, signed in to join |
| GET | /orgs/:orgId/members | member (emails and invites shown to admins) |
| POST, DELETE | /orgs/:orgId/invites, /orgs/:orgId/invites/:id | admin (only the owner can invite admins) |
| PATCH | /orgs/:orgId/members/:userId | owner |
| DELETE | /orgs/:orgId/members/:userId | admin (only the owner can remove admins) |
| GET | /invites/:token | public |
| POST | /invites/:token/accept | signed in, email must match the invite |

Errors always look like `{ "error": { "message": "...", "fields"?: {...} } }`.

## Not built yet

Nothing major. See below for tests.

## Tests

```bash
bun run test                 # validation and auth guard tests, no database needed
RUN_DB_TESTS=1 bun run test  # full workflow against an in-memory MongoDB (downloads a mongod binary on first run)
```

The full workflow test mocks Resend and file storage, and covers verification, roles, invitations, uploads, approvals, notifications, organization isolation, expired invites and password reset.
