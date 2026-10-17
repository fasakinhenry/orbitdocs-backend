# OrbitDocs backend

The OrbitDocs API powers a collaborative document platform for personal
workspaces and organizations. It provides authentication, organization
membership, file storage, folder permissions, approvals, notifications, and
administration for the OrbitDocs frontend.

> Check it out here: https://orbitdoc.vercel.app

> Built with 💖 by [Fasakin Henry](https://github.com/fasakinhenry)

## Product capabilities

The backend supports:

- Personal workspaces created automatically for every account.
- Organization creation with public or private visibility.
- Public organization discovery and membership requests.
- Email, username, invitation-token, and shareable-link onboarding.
- In-app invitations and notifications when email delivery is unavailable.
- Owner, administrator, and member roles.
- Public and private folders with per-member permissions.
- Folder-level view, upload, edit, delete, and manager access.
- File upload, download, preview URLs, starring, search, sorting, pagination,
  copy, and move operations.
- File approval workflows, including submit, approve, return to draft, and
  withdraw submission.
- Deletion requests that require approval from authorized folder managers.
- Profile management, avatars, social links, profile visibility, and default
  file-view preferences.
- Storage quotas, per-file limits, organization suspension, and platform
  administration.

Folder visibility is enforced server-side. A member who does not have view
access cannot see the folder or the files inside it, even if they know the
folder or document identifier.

## Storage

Files live in any S3 compatible bucket. Set `STORAGE_PROVIDER` and the matching values in `.env`.

- **Backblaze B2** (free 10 GB, no card needed to start): create a private bucket, create an application key limited to that bucket, set `STORAGE_PROVIDER=b2`, `STORAGE_REGION` (for example `us-west-004`), the key ID and key, and the bucket name.
- **AWS S3**: `STORAGE_PROVIDER=s3` with `STORAGE_REGION`.
- **Cloudflare R2**: `STORAGE_PROVIDER=r2` with `STORAGE_ENDPOINT=https://ACCOUNT_ID.r2.cloudflarestorage.com`.
- **Anything else S3 compatible** (Wasabi, MinIO, Spaces): `STORAGE_PROVIDER=custom` with `STORAGE_ENDPOINT`.

Switching provider later is an env change. Existing files do not move automatically, so copy the bucket contents first.

For Backblaze B2, the values must be configured as separate credentials:

```env
STORAGE_PROVIDER=b2
STORAGE_REGION=us-east-005
STORAGE_ENDPOINT=
STORAGE_ACCESS_KEY_ID=<the application key ID>
STORAGE_SECRET_ACCESS_KEY=<the application key secret>
STORAGE_BUCKET=orbitdocs
```

For a bucket whose endpoint is `s3.us-east-005.backblazeb2.com`, `STORAGE_REGION` must be
`us-east-005`. Do not use the bucket ID as `STORAGE_BUCKET`; use the bucket's exact name.
The application key ID and application key secret are different values. Never put the ID in
both fields. The generated key must have read and write access to the bucket.

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

`owner` > `admin` > `member`.

- **Owner**: full organization access, member and administrator management,
  organization deletion, folder management, approvals, and storage controls.
- **Admin**: organization administration, invitations, member requests,
  folder administration, approvals, and activity access where permitted.
- **Member**: access to the folders and files explicitly available to them,
  including upload, search, download, and file workflows allowed by folder
  permissions.

Folder manager access is separate from the organization role hierarchy. An
administrator or selected member can manage one folder without automatically
seeing other private folders. Non-members receive a 404 for organization
routes.

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
| PATCH, DELETE | /orgs/:orgId/folders/:folderId | folder manager or owner |
| GET, PATCH | /orgs/:orgId/folders/:folderId/access | folder manager or owner |
| GET | /orgs/:orgId/documents?view&folder&q&sort&dir&page&limit | member |
| POST | /orgs/:orgId/documents (multipart: files, folderId) | member |
| GET | /orgs/:orgId/documents/:id | member with folder access |
| POST | /orgs/:orgId/documents/copy, /move | member with source and destination access |
| POST | /orgs/:orgId/documents/star | member |
| POST | /orgs/:orgId/documents/submit | member (own drafts only) |
| POST | /orgs/:orgId/documents/trash, /restore, /status | admin |
| POST | /orgs/:orgId/documents/delete-request, /delete-decision | member, folder manager |
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

## Storage and security model

The API uses signed URLs for file access and stores file contents in an
S3-compatible provider. File metadata and permissions are stored in MongoDB.
Access tokens are short-lived, refresh tokens use an httpOnly cookie, and
organization boundaries are checked on every protected route.

Delete requests are recorded separately from immediate file deletion. This
allows folder managers and organization owners to review destructive actions
before files enter the trash.

## Tests

```bash
bun run test                 # validation and auth guard tests, no database needed
RUN_DB_TESTS=1 bun run test  # full workflow against an in-memory MongoDB (downloads a mongod binary on first run)
```

The full workflow test mocks Resend and file storage, and covers verification, roles, invitations, uploads, approvals, notifications, organization isolation, expired invites and password reset.

> Built with 💖 by [Fasakin Henry](https://github.com/fasakinhenry)
