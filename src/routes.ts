import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { Router, type Request } from 'express'
import { z } from 'zod'
import bcrypt from 'bcryptjs'
import multer from 'multer'
import { Types } from 'mongoose'
import rateLimit from 'express-rate-limit'
import { Resend } from 'resend'
import { env } from './config'
import { Audit, Doc, Folder, Invite, JoinLink, JoinRequest, Membership, Note, Org, Token, User } from './models'
import { MB, getSettings, orgQuota, usedBytes } from './platform'
import { audit, auth, clearRefresh, copy, del, h, HttpError, member, orgOf, put, setRefresh, signAccess, signedGet, verifyRefresh } from './lib'

const r = Router()
const resend = new Resend(env.RESEND_API_KEY)
const notify = (users: Types.ObjectId[], org: Types.ObjectId, text: string) =>
  users.length ? Note.insertMany(users.map((user) => ({ user, org, text }))) : Promise.resolve([])
const sha = (t: string) => createHash('sha256').update(t).digest('hex')
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)
const oid = z.string().regex(/^[a-f\d]{24}$/i)
const USERNAME = /^[a-z0-9_]{3,20}$/
const RESERVED = ['admin', 'administrator', 'support', 'orbitdocs', 'root', 'help', 'system', 'staff']
const SEED_FOLDERS = ['Partnerships & Collaborations', 'Events', 'Design & Branding', 'Technical Documentation', 'Content & Social Media', 'Community Operations', 'Archive']
const idList = z.object({ ids: z.array(oid).min(1).max(100) })
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * MB, files: 5 } })
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, skip: () => env.NODE_ENV === 'test' })

interface DocLean {
  _id: Types.ObjectId; name: string; folder: Types.ObjectId; owner?: { _id: Types.ObjectId; name: string }
  size: number; status: string; starredBy: Types.ObjectId[]; trashed: boolean; updatedAt: Date; createdAt: Date; mime?: string
  deleteRequestedBy?: Types.ObjectId; deleteRequestedAt?: Date
}
const dto = (d: DocLean, uid: string) => ({
  id: String(d._id), name: d.name, folderId: String(d.folder), owner: d.owner?.name ?? 'Former member', ownerId: d.owner ? String(d.owner._id) : '',
  size: d.size, modified: d.updatedAt, status: d.status, trashed: d.trashed, mime: d.mime,
  deleteRequested: !!d.deleteRequestedAt,
  starred: d.starredBy.some((s) => String(s) === uid),
})
const withOwner = (ids: Types.ObjectId[]) => Doc.find({ _id: { $in: ids } }).populate('owner', 'name').lean<DocLean[]>()

// ---------- auth ----------
const pub = (u: { _id: unknown; name: string; username: string; email: string; emailVerified?: boolean; avatarKey?: string; bio?: string; socialLinks?: Map<string, string> | Record<string, string>; profilePublic?: boolean; defaultView?: 'list' | 'grid' }) => ({
  id: String(u._id), name: u.name, username: u.username, email: u.email, emailVerified: !!u.emailVerified,
  isAdmin: !!u.emailVerified && u.email === env.ADMIN_EMAIL.toLowerCase(),
  avatarUrl: null as string | null, bio: u.bio ?? '', socialLinks: u.socialLinks ?? {}, profilePublic: u.profilePublic !== false, defaultView: u.defaultView ?? 'list',
})

async function mail(to: string, subject: string, heading: string, text: string, cta: string, link: string, note: string) {
  const { error } = await resend.emails.send({
    from: env.MAIL_FROM, to, subject,
    html: `<div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;padding:24px;color:#0f172a">
      <h2 style="margin:0 0 12px">${esc(heading)}</h2>
      <p style="color:#475569;line-height:1.6">${esc(text)}</p>
      <p><a href="${link}" style="display:inline-block;background:#287bff;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">${esc(cta)}</a></p>
      <p style="color:#94a3b8;font-size:13px">${esc(note)}</p></div>`,
  })
  return error
}
async function issue(user: Types.ObjectId, kind: 'verify' | 'reset', hours: number) {
  await Token.deleteMany({ user, kind, usedAt: null })
  const raw = randomBytes(32).toString('hex')
  await Token.create({ user, kind, tokenHash: sha(raw), expiresAt: new Date(Date.now() + hours * 36e5) })
  return raw
}
const sendVerify = async (u: { _id: Types.ObjectId; email: string }) =>
  mail(u.email, 'Verify your email for OrbitDocs', 'Confirm your email', 'Use the button below to finish setting up your OrbitDocs account.', 'Verify email',
    `${env.CLIENT_URL}/verify/${await issue(u._id, 'verify', 24)}`, 'This link expires in 24 hours.')

async function deleteOrganization(id: Types.ObjectId) {
  const org = await Org.findById(id)
  if (!org) throw new HttpError(404, 'Workspace not found.')
  const docs = await Doc.find({ org: id }).select('key').lean()
  await Promise.all(docs.map((d) => del(d.key)))
  await Promise.all([
    Doc.deleteMany({ org: id }), Folder.deleteMany({ org: id }), Membership.deleteMany({ org: id }),
    Invite.deleteMany({ org: id }), JoinLink.deleteMany({ org: id }), JoinRequest.deleteMany({ org: id }),
    Note.deleteMany({ org: id }), Audit.deleteMany({ org: id }),
  ])
  if (org.logoKey) await del(org.logoKey)
  await org.deleteOne()
}

r.post('/auth/register', authLimit, h(async (req, res) => {
  const b = z.object({
    name: z.string().trim().min(2).max(80),
    username: z.string().trim().toLowerCase().regex(USERNAME, 'Use 3 to 20 letters, numbers, or underscores.'),
    email: z.string().trim().toLowerCase().email(),
    password: z.string().min(8).max(128),
  }).parse(req.body)
  if (!(await getSettings()).registrationOpen && b.email !== env.ADMIN_EMAIL.toLowerCase()) throw new HttpError(403, 'Sign ups are closed right now.')
  if (RESERVED.includes(b.username) || (await User.exists({ username: b.username }))) throw new HttpError(409, 'That username is taken.')
  if (await User.exists({ email: b.email })) throw new HttpError(409, 'An account with this email already exists.')
  const u = await User.create({ name: b.name, username: b.username, email: b.email, passwordHash: await bcrypt.hash(b.password, 12) })
  const personal = await Org.create({ name: `${u.name}'s Personal Workspace`, slug: `${u.username}-${randomBytes(4).toString('hex')}`, type: 'Personal', description: 'Your private workspace.', visibility: 'private', personal: true })
  await Membership.create({ user: u._id, org: personal._id, role: 'owner' })
  await sendVerify(u).catch(() => undefined)
  setRefresh(res, u.id)
  res.status(201).json({ user: pub(u), accessToken: signAccess(u.id) })
}))

r.post('/auth/login', authLimit, h(async (req, res) => {
  const b = z.object({ identifier: z.string().trim().toLowerCase().min(3).max(254), password: z.string().min(1) }).parse(req.body)
  const u = await User.findOne(b.identifier.includes('@') ? { email: b.identifier } : { username: b.identifier.replace(/^@/, '') })
  if (!u || !(await bcrypt.compare(b.password, u.passwordHash))) throw new HttpError(401, 'Incorrect email, username, or password.')
  if (u.suspended) throw new HttpError(403, 'This account has been suspended.')
  setRefresh(res, u.id)
  res.json({ user: pub(u), accessToken: signAccess(u.id) })
}))

r.post('/auth/refresh', h(async (req, res) => {
  const p = verifyRefresh(req.cookies?.rt)
  const u = p ? await User.findById(p.sub) : null
  // A password reset invalidates every session that started before it.
  if (!p || !u || u.suspended || (u.passwordChangedAt && p.iat * 1000 <= u.passwordChangedAt.getTime())) { clearRefresh(res); throw new HttpError(401, 'Your session has expired. Sign in again.') }
  res.json({ accessToken: signAccess(p.sub) })
}))

r.get('/auth/username/:name', authLimit, h(async (req, res) => {
  const n = req.params.name.toLowerCase()
  res.json({ available: USERNAME.test(n) && !RESERVED.includes(n) && !(await User.exists({ username: n })) })
}))

r.post('/auth/verify/send', authLimit, auth, h(async (req, res) => {
  const u = await User.findById(req.uid)
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  if (!u.emailVerified && (await sendVerify(u))) throw new HttpError(502, 'We could not send the email. Try again in a moment.')
  res.status(204).end()
}))

r.post('/auth/verify', authLimit, h(async (req, res) => {
  const { token } = z.object({ token: tokenParam }).parse(req.body)
  const t = await Token.findOne({ tokenHash: sha(token), kind: 'verify', usedAt: null, expiresAt: { $gt: new Date() } })
  if (!t) throw new HttpError(400, 'This link is invalid or has expired.')
  await User.updateOne({ _id: t.user }, { emailVerified: true })
  t.usedAt = new Date()
  await t.save()
  res.status(204).end()
}))

// Always answers the same way so the form cannot be used to find out which emails have accounts.
r.post('/auth/forgot', authLimit, h(async (req, res) => {
  const { email } = z.object({ email: z.string().trim().toLowerCase().email() }).parse(req.body)
  const u = await User.findOne({ email })
  if (u) {
    const raw = await issue(u._id, 'reset', 1)
    await mail(u.email, 'Reset your OrbitDocs password', 'Reset your password', 'We received a request to reset your password. If it was not you, you can ignore this email.',
      'Choose a new password', `${env.CLIENT_URL}/reset/${raw}`, 'This link expires in 1 hour.').catch(() => undefined)
  }
  res.status(204).end()
}))

r.post('/auth/reset', authLimit, h(async (req, res) => {
  const b = z.object({ token: tokenParam, password: z.string().min(8).max(128) }).parse(req.body)
  const t = await Token.findOne({ tokenHash: sha(b.token), kind: 'reset', usedAt: null, expiresAt: { $gt: new Date() } })
  if (!t) throw new HttpError(400, 'This link is invalid or has expired. Request a new one.')
  await User.updateOne({ _id: t.user }, { passwordHash: await bcrypt.hash(b.password, 12), passwordChangedAt: new Date(), emailVerified: true })
  t.usedAt = new Date()
  await t.save()
  clearRefresh(res)
  res.status(204).end()
}))

r.post('/auth/logout', (_req, res) => { clearRefresh(res); res.status(204).end() })

r.get('/auth/me', auth, h(async (req, res) => {
  const u = await User.findById(req.uid)
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  const ms = await Membership.find({ user: u.id }).populate<{ org: { _id: Types.ObjectId; name: string; slug: string; type: string; description?: string; logoKey?: string; visibility?: 'public' | 'private'; personal?: boolean } }>('org').lean()
  const orgs = await Promise.all(ms.map(async (m) => ({
    id: String(m.org._id), name: m.org.name, slug: m.org.slug, type: m.org.type, description: m.org.description ?? '', role: m.role,
    visibility: m.org.visibility ?? 'public', personal: !!m.org.personal,
    logoUrl: m.org.logoKey ? await signedGet(m.org.logoKey) : null,
  })))
  const user = pub(u)
  user.avatarUrl = u.avatarKey ? await signedGet(u.avatarKey) : null
  res.json({ user, organizations: orgs })
}))

// ---------- organizations ----------
r.post('/orgs', auth, h(async (req, res) => {
  const b = z.object({
    name: z.string().trim().min(2).max(80),
    slug: z.string().regex(/^[a-z0-9-]{3,30}$/, 'Use 3 to 30 lowercase letters, numbers, or hyphens.'),
    type: z.enum(['Student community', 'Nonprofit', 'Startup', 'Company', 'Educational institution', 'Professional community', 'Other']),
    description: z.string().trim().max(300).default(''),
    visibility: z.enum(['public', 'private']).default('public'),
  }).parse(req.body)
  if (await Org.exists({ slug: b.slug })) throw new HttpError(409, 'That URL name is taken.')
  const org = await Org.create(b)
  await Membership.create({ user: req.uid, org: org._id, role: 'owner' })
  await Folder.insertMany(SEED_FOLDERS.map((name) => ({ org: org._id, name })))
  await audit(org._id, req.uid!, 'org.create', org.name)
  res.status(201).json({ id: org.id, name: org.name, slug: org.slug, type: org.type, role: 'owner', logoUrl: null })
}))

r.get('/profile/:username', authLimit, h(async (req, res) => {
  const u = await User.findOne({ username: req.params.username.toLowerCase() }).select('name username avatarKey bio socialLinks profilePublic')
  if (!u || !u.profilePublic) throw new HttpError(404, 'Profile not found.')
  res.json({ id: String(u._id), name: u.name, username: u.username, avatarUrl: u.avatarKey ? await signedGet(u.avatarKey) : null, bio: u.bio ?? '', socialLinks: u.socialLinks ?? {} })
}))

r.patch('/profile', auth, h(async (req, res) => {
  const b = z.object({
    name: z.string().trim().min(2).max(80).optional(),
    bio: z.string().trim().max(500).optional(),
    socialLinks: z.record(z.string().trim().max(200)).optional(),
    profilePublic: z.boolean().optional(),
    defaultView: z.enum(['list', 'grid']).optional(),
  }).parse(req.body)
  const u = await User.findByIdAndUpdate(req.uid, b, { new: true })
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  const user = pub(u)
  user.avatarUrl = u.avatarKey ? await signedGet(u.avatarKey) : null
  res.json({ user })
}))

r.delete('/profile', auth, h(async (req, res) => {
  const id = new Types.ObjectId(req.uid!)
  const ownedOrgs = await Membership.find({ user: id, role: 'owner' }).populate<{ org: { _id: Types.ObjectId; personal?: boolean } }>('org', '_id personal').lean()
  if (ownedOrgs.some((m) => !m.org.personal)) throw new HttpError(409, 'Delete organizations you own before deleting your profile.')
  const u = await User.findById(id)
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  await Promise.all(ownedOrgs.map((m) => deleteOrganization(m.org._id)))
  const docs = await Doc.find({ owner: id }).select('key').lean()
  await Promise.all(docs.map((d) => del(d.key)))
  if (u.avatarKey) await del(u.avatarKey)
  await Promise.all([
    Doc.deleteMany({ owner: id }), Membership.deleteMany({ user: id }), Token.deleteMany({ user: id }),
    Note.deleteMany({ user: id }), Invite.deleteMany({ email: u.email }), JoinRequest.deleteMany({ user: id }),
  ])
  await u.deleteOne()
  res.status(204).end()
}))

r.post('/profile/avatar', auth, upload.single('avatar'), h(async (req, res) => {
  const f = req.file
  if (!f || !f.mimetype.startsWith('image/') || f.size > 2_000_000) throw new HttpError(400, 'Choose an image under 2 MB.')
  const key = `profiles/${req.uid}/${randomUUID()}`
  await put(key, f.buffer, f.mimetype)
  const u = await User.findByIdAndUpdate(req.uid, { avatarKey: key }, { new: true })
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  res.json({ user: { ...pub(u), avatarUrl: await signedGet(key) } })
}))

const o = Router({ mergeParams: true })
r.use('/orgs/:orgId', auth, o)

r.delete('/orgs/:orgId', auth, h(async (req, res) => {
  const id = oid.parse(req.params.orgId)
  const u = await User.findById(req.uid).select('email emailVerified')
  const membership = await Membership.findOne({ org: id, user: req.uid }).select('role')
  const superadmin = !!u?.emailVerified && u.email === env.ADMIN_EMAIL.toLowerCase()
  if (!superadmin && membership?.role !== 'owner') throw new HttpError(403, 'Only the organization creator or platform administrator can delete this workspace.')
  await deleteOrganization(new Types.ObjectId(id))
  res.status(204).end()
}))

o.patch('/', member('admin'), h(async (req, res) => {
  const b = z.object({ name: z.string().trim().min(2).max(80), description: z.string().trim().max(300), visibility: z.enum(['public', 'private']).default('public') }).parse(req.body)
  await Org.updateOne({ _id: orgOf(req) }, b)
  await audit(orgOf(req), req.uid!, 'org.update', b.name)
  res.status(204).end()
}))

r.get('/organizations/public', authLimit, h(async (_req, res) => {
  const items = await Org.find({ visibility: 'public', personal: false, suspended: false }).sort({ name: 1 }).limit(100).select('name slug type description logoKey').lean()
  res.json({ items: items.map((o) => ({ id: String(o._id), name: o.name, slug: o.slug, type: o.type, description: o.description ?? '', logoUrl: null })) })
}))

r.post('/organizations/:orgId/request', auth, h(async (req, res) => {
  const org = await Org.findOne({ _id: oid.parse(req.params.orgId), visibility: 'public', personal: false, suspended: false })
  if (!org) throw new HttpError(404, 'Organization not found.')
  if (await Membership.exists({ org: org._id, user: req.uid })) throw new HttpError(409, 'You are already a member.')
  const request = await JoinRequest.findOneAndUpdate({ org: org._id, user: req.uid }, { status: 'pending' }, { upsert: true, new: true })
  const admins = await Membership.find({ org: org._id, role: { $in: ['owner', 'admin'] } }).select('user').lean()
  const requester = await User.findById(req.uid).select('name')
  await notify(admins.map((m) => m.user), org._id, `${requester?.name ?? 'Someone'} requested to join ${org.name}`)
  res.status(201).json({ id: String(request._id) })
}))

o.get('/notifications', member('member'), h(async (req, res) => {
  const f = { org: orgOf(req), user: new Types.ObjectId(req.uid!) }
  const [items, unread] = await Promise.all([Note.find(f).sort({ createdAt: -1 }).limit(20).lean(), Note.countDocuments({ ...f, readAt: null })])
  res.json({ unread, items: items.map((n) => ({ id: String(n._id), text: n.text, at: n.createdAt, read: !!n.readAt })) })
}))

o.post('/notifications/read', member('member'), h(async (req, res) => {
  await Note.updateMany({ org: orgOf(req), user: new Types.ObjectId(req.uid!), readAt: null }, { readAt: new Date() })
  res.status(204).end()
}))

o.post('/logo', member('admin'), upload.single('logo'), h(async (req, res) => {
  const f = req.file
  if (!f || !f.mimetype.startsWith('image/') || f.size > 1_000_000) throw new HttpError(400, 'Upload an image under 1 MB.')
  const key = `${req.params.orgId}/logo-${randomUUID()}`
  await put(key, f.buffer, f.mimetype)
  await Org.updateOne({ _id: req.params.orgId }, { logoKey: key })
  await audit(orgOf(req), req.uid!, 'org.logo')
  res.json({ logoUrl: await signedGet(key) })
}))

// ---------- folders ----------
type FolderAccess = { user: Types.ObjectId; view?: boolean; upload?: boolean; edit?: boolean; delete?: boolean; manage?: boolean }
const folderPermission = (folder: { visibility?: string; access?: FolderAccess[] }, req: Request, permission: 'view' | 'upload' | 'edit' | 'delete' | 'manage') =>
  req.role === 'owner' ||
  (folder.visibility !== 'private' && ['view', 'upload', 'edit'].includes(permission)) ||
  !!folder.access?.find((a) => String(a.user) === req.uid && a[permission])
const visibleFolderIds = async (req: Request) => {
  const folders = await Folder.find({ org: orgOf(req) }).select('_id visibility access').lean()
  return folders.filter((f) => f.visibility !== 'private' || folderPermission(f, req, 'view')).map((f) => f._id)
}

o.get('/folders', member('member'), h(async (req, res) => {
  const org = orgOf(req)
  const [folders, counts] = await Promise.all([
    Folder.find({ org }).sort({ createdAt: 1 }).lean(),
    Doc.aggregate<{ _id: Types.ObjectId; count: number }>([{ $match: { org, trashed: false } }, { $group: { _id: '$folder', count: { $sum: 1 } } }]),
  ])
  const n = new Map(counts.map((c) => [String(c._id), c.count]))
  const visible = req.role === 'owner' ? folders : folders.filter((f) => f.visibility !== 'private' || f.access?.some((a) => String(a.user) === req.uid && a.view))
  res.json({ items: visible.map((f) => ({ id: String(f._id), name: f.name, visibility: f.visibility ?? 'public', canManage: req.role !== 'member' || !!f.access?.some((a) => String(a.user) === req.uid && a.manage), count: n.get(String(f._id)) ?? 0, updated: f.updatedAt })) })
}))

o.post('/folders', member('admin'), h(async (req, res) => {
  const { name, visibility } = z.object({ name: z.string().trim().min(1).max(80), visibility: z.enum(['public', 'private']).default('public') }).parse(req.body)
  const org = orgOf(req)
  if (await Folder.exists({ org, name }).collation({ locale: 'en', strength: 2 })) throw new HttpError(409, 'A folder with this name already exists.')
  const f = await Folder.create({ org, name, visibility })
  await audit(org, req.uid!, 'folder.create', name)
  res.status(201).json({ id: f.id, name: f.name, visibility: f.visibility, count: 0, updated: f.updatedAt })
}))

o.patch('/folders/:folderId', member('member'), h(async (req, res) => {
  const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(req.body)
  const folderId = oid.parse(req.params.folderId)
  const org = orgOf(req)
  if (await Folder.exists({ org, name, _id: { $ne: folderId } }).collation({ locale: 'en', strength: 2 })) throw new HttpError(409, 'A folder with this name already exists.')
  const folder = await Folder.findOne({ _id: folderId, org })
  if (!folder) throw new HttpError(404, 'Folder not found.')
  if (req.role === 'member' && !folderPermission(folder, req, 'manage')) throw new HttpError(403, 'Only folder managers can rename this folder.')
  folder.name = name
  await folder.save()
  await audit(org, req.uid!, 'folder.rename', `${folder.name}`)
  res.status(204).end()
}))

o.post('/folders/:folderId/duplicate', member('member'), h(async (req, res) => {
  const folderId = oid.parse(req.params.folderId)
  const org = orgOf(req)
  const folder = await Folder.findOne({ _id: folderId, org })
  if (!folder) throw new HttpError(404, 'Folder not found.')
  if (req.role === 'member' && !folderPermission(folder, req, 'manage')) throw new HttpError(403, 'Only folder managers can duplicate this folder.')
  const base = `Copy of ${folder.name}`
  let name = base
  for (let i = 2; await Folder.exists({ org, name }).collation({ locale: 'en', strength: 2 }); i++) name = `${base} ${i}`
  const copy = await Folder.create({ org, name, visibility: folder.visibility, access: folder.access })
  await audit(org, req.uid!, 'folder.duplicate', `${folder.name} -> ${copy.name}`)
  res.status(201).json({ id: copy.id, name: copy.name, count: 0, updated: copy.updatedAt })
}))

o.delete('/folders/:folderId', member('member'), h(async (req, res) => {
  const folderId = oid.parse(req.params.folderId)
  const folder = await Folder.findOne({ _id: folderId, org: orgOf(req) })
  if (!folder) throw new HttpError(404, 'Folder not found.')
  if (req.role === 'member' && !folderPermission(folder, req, 'manage')) throw new HttpError(403, 'Only folder managers can delete this folder.')
  if (await Doc.exists({ folder: folderId })) throw new HttpError(409, 'Move or delete the files in this folder before deleting it.')
  await folder.deleteOne()
  await audit(orgOf(req), req.uid!, 'folder.delete', folder.name)
  res.status(204).end()
}))

o.patch('/folders/:folderId/access', member('member'), h(async (req, res) => {
  const b = z.object({
    userId: oid,
    view: z.boolean(),
    upload: z.boolean(),
    edit: z.boolean(),
    delete: z.boolean(),
    manage: z.boolean().default(false),
  }).parse(req.body)
  const folder = await Folder.findOne({ _id: oid.parse(req.params.folderId), org: orgOf(req) })
  if (!folder || !(await Membership.exists({ org: orgOf(req), user: b.userId }))) throw new HttpError(404, 'Folder or member not found.')
  if (req.role === 'member' && !folderPermission(folder, req, 'manage')) throw new HttpError(403, 'Only folder managers can edit folder access.')
  const access = folder.access as FolderAccess[]
  folder.access = access.filter((a) => String(a.user) !== b.userId)
  if (b.view || b.upload || b.edit || b.delete || b.manage) folder.access.push({ user: b.userId, view: b.view, upload: b.upload, edit: b.edit, delete: b.delete, manage: b.manage } as never)
  await folder.save()
  res.status(204).end()
}))

o.get('/folders/:folderId/access', member('member'), h(async (req, res) => {
  const folder = await Folder.findOne({ _id: oid.parse(req.params.folderId), org: orgOf(req) }).lean()
  if (!folder) throw new HttpError(404, 'Folder not found.')
  if (req.role === 'member' && !folderPermission(folder, req, 'manage')) throw new HttpError(403, 'Only folder managers can view folder access.')
  const members = await Membership.find({ org: orgOf(req) }).populate<{ user: { _id: Types.ObjectId; name: string; username: string } }>('user', 'name username').lean()
  const access = new Map((folder.access ?? []).map((a) => [String(a.user), a]))
  res.json({ items: members.map((m) => ({ id: String(m.user._id), name: m.user.name, username: m.user.username, view: m.role === 'owner' || folder.visibility !== 'private' || !!access.get(String(m.user._id))?.view, upload: m.role === 'owner' || folder.visibility !== 'private' || !!access.get(String(m.user._id))?.upload, edit: m.role === 'owner' || folder.visibility !== 'private' || !!access.get(String(m.user._id))?.edit, delete: !!access.get(String(m.user._id))?.delete, manage: m.role === 'owner' || !!access.get(String(m.user._id))?.manage })) })
}))

// ---------- documents ----------
o.get('/documents', member('member'), h(async (req, res) => {
  const q = z.object({
    view: z.enum(['all', 'recent', 'starred', 'trash']).default('all'),
    folder: oid.optional(), q: z.string().max(100).optional(),
    sort: z.enum(['name', 'modified', 'size']).default('modified'), dir: z.enum(['asc', 'desc']).default('desc'),
    page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(100).default(25),
  }).parse(req.query)
  const f: Record<string, unknown> = { org: orgOf(req), trashed: q.view === 'trash' }
  if (req.role !== 'owner') f.folder = { $in: await visibleFolderIds(req) }
  if (q.view === 'starred') f.starredBy = new Types.ObjectId(req.uid!)
  if (q.folder) {
    const allowed = q.folder === String((await visibleFolderIds(req)).find((id) => String(id) === q.folder))
    if (!allowed) throw new HttpError(404, 'Folder not found.')
    f.folder = q.folder
  }
  if (q.q) f.name = { $regex: q.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' }
  const field = { name: 'name', modified: 'updatedAt', size: 'size' }[q.sort]
  const [items, total] = await Promise.all([
    Doc.find(f).sort({ [field]: q.dir === 'asc' ? 1 : -1 }).skip((q.page - 1) * q.limit).limit(q.limit).populate('owner', 'name').lean<DocLean[]>(),
    Doc.countDocuments(f),
  ])
  res.json({ items: items.map((d) => dto(d, req.uid!)), total, page: q.page, limit: q.limit })
}))

o.post('/documents', member('member'), upload.array('files', 10), h(async (req: Request, res) => {
  const { folderId } = z.object({ folderId: oid }).parse(req.body)
  const org = orgOf(req)
  if (!(await Folder.exists({ _id: folderId, org }))) throw new HttpError(404, 'Folder not found.')
  if (req.role !== 'owner') {
      const folder = await Folder.findById(folderId).select('visibility access')
      if (!folder || !folderPermission(folder, req, 'upload')) throw new HttpError(403, 'You do not have upload access to this folder.')
  }
  const files = (req.files as Express.Multer.File[] | undefined) ?? []
  if (!files.length) throw new HttpError(400, 'Choose at least one file.')
  const [cfg, used, quota] = await Promise.all([getSettings(), usedBytes(org), orgQuota(org)])
  if (files.some((f) => f.size > cfg.maxFileMB * MB)) throw new HttpError(413, `Files can be up to ${cfg.maxFileMB} MB each.`)
  if (used + files.reduce((n, f) => n + f.size, 0) > quota) throw new HttpError(413, 'This workspace is out of storage. Delete files you no longer need, or contact support to raise the limit.')
  const created: Types.ObjectId[] = []
  for (const f of files) {
    const key = `${org}/${randomUUID()}`
    await put(key, f.buffer, f.mimetype)
    const d = await Doc.create({ org, folder: folderId, owner: req.uid, name: f.originalname, key, mime: f.mimetype, size: f.size })
    created.push(d._id)
  }
  await Folder.updateOne({ _id: folderId }, { $set: { updatedAt: new Date() } })
  await audit(org, req.uid!, 'document.upload', `${files.length} file(s)`)
  res.status(201).json({ items: (await withOwner(created)).map((d) => dto(d, req.uid!)) })
}))

o.post('/documents/star', member('member'), h(async (req, res) => {
  const b = idList.extend({ starred: z.boolean() }).parse(req.body)
  const me = new Types.ObjectId(req.uid!)
  await Doc.updateMany({ org: orgOf(req), _id: { $in: b.ids } }, b.starred ? { $addToSet: { starredBy: me } } : { $pull: { starredBy: me } })
  res.status(204).end()
}))

o.post('/documents/trash', member('admin'), h(async (req, res) => {
  const { ids } = idList.parse(req.body)
  const docs = await Doc.find({ org: orgOf(req), _id: { $in: ids } }).select('folder')
  for (const d of docs) {
    const folder = await Folder.findById(d.folder).select('access')
    if (req.role !== 'owner' && !folderPermission(folder ?? {}, req, 'manage')) throw new HttpError(403, 'Only folder managers can delete files in this folder.')
  }
  const x = await Doc.updateMany({ org: orgOf(req), _id: { $in: ids } }, { trashed: true })
  await audit(orgOf(req), req.uid!, 'document.trash', `${x.modifiedCount} file(s)`)
  res.status(204).end()
}))

o.post('/documents/restore', member('admin'), h(async (req, res) => {
  const { ids } = idList.parse(req.body)
  const docs = await Doc.find({ org: orgOf(req), _id: { $in: ids } }).select('folder')
  for (const d of docs) {
    const folder = await Folder.findById(d.folder).select('access')
    if (req.role !== 'owner' && !folderPermission(folder ?? {}, req, 'manage')) throw new HttpError(403, 'Only folder managers can restore files in this folder.')
  }
  const x = await Doc.updateMany({ org: orgOf(req), _id: { $in: ids } }, { trashed: false })
  await audit(orgOf(req), req.uid!, 'document.restore', `${x.modifiedCount} file(s)`)
  res.status(204).end()
}))

// Members can send their own drafts for review. Only admins can approve or return documents.
o.post('/documents/submit', member('member'), h(async (req, res) => {
  const { ids } = idList.parse(req.body)
  const current = await Doc.find({ org: orgOf(req), _id: { $in: ids }, owner: req.uid, trashed: false }).select('status').lean()
  const pending = current.filter((d) => d.status === 'pending').map((d) => d._id)
  const draft = current.filter((d) => d.status === 'draft').map((d) => d._id)
  if (pending.length) await Doc.updateMany({ _id: { $in: pending } }, { status: 'draft' })
  const x = await Doc.updateMany({ _id: { $in: draft } }, { status: 'pending' })
  if (x.modifiedCount) {
    const [me, admins] = await Promise.all([
      User.findById(req.uid).select('name'),
      Membership.find({ org: orgOf(req), role: { $in: ['admin', 'owner'] }, user: { $ne: new Types.ObjectId(req.uid!) } }).select('user').lean(),
    ])
    await audit(orgOf(req), req.uid!, 'document.submit', `${x.modifiedCount} file(s)`)
    await notify(admins.map((a) => a.user), orgOf(req), `${me?.name ?? 'A member'} submitted ${x.modifiedCount === 1 ? 'a file' : `${x.modifiedCount} files`} for approval`)
  }
  res.status(204).end()
}))

o.post('/documents/status', member('admin'), h(async (req, res) => {
  const b = idList.extend({ status: z.enum(['draft', 'pending', 'approved']) }).parse(req.body)
  const docsForAccess = await Doc.find({ org: orgOf(req), _id: { $in: b.ids } }).select('folder')
  for (const d of docsForAccess) {
    const folder = await Folder.findById(d.folder).select('access')
    if (req.role !== 'owner' && !folderPermission(folder ?? {}, req, 'manage')) throw new HttpError(403, 'Only folder managers can approve files in this folder.')
  }
  await Doc.updateMany({ org: orgOf(req), _id: { $in: b.ids } }, { status: b.status })
  await audit(orgOf(req), req.uid!, `document.${b.status}`, `${b.ids.length} file(s)`)
  if (b.status !== 'pending') {
    const docs = await Doc.find({ org: orgOf(req), _id: { $in: b.ids }, owner: { $ne: new Types.ObjectId(req.uid!) } }).select('owner name').limit(50).lean()
    await Note.insertMany(docs.map((d) => ({ user: d.owner, org: orgOf(req), text: `"${d.name}" ${b.status === 'approved' ? 'was approved' : 'was returned to draft'}` })))
  }
  res.status(204).end()
}))

o.post('/documents/delete-request', member('member'), h(async (req, res) => {
  const { ids } = idList.parse(req.body)
  const docs = await Doc.find({ org: orgOf(req), _id: { $in: ids }, trashed: false })
  const allowed: typeof docs = []
  for (const d of docs) {
    const folder = await Folder.findById(d.folder).select('access')
    if (req.role === 'owner' || folderPermission(folder ?? {}, req, 'delete')) allowed.push(d)
  }
  if (!allowed.length) throw new HttpError(403, 'You do not have delete access to these files.')
  await Doc.updateMany({ _id: { $in: allowed.map((d) => d._id) } }, { deleteRequestedBy: req.uid, deleteRequestedAt: new Date() })
  const managers = await Membership.find({ org: orgOf(req), role: { $in: ['owner', 'admin'] } }).select('user').lean()
  await notify(managers.map((m) => m.user), orgOf(req), `${allowed.length} file deletion ${allowed.length === 1 ? 'request' : 'requests'} need approval`)
  res.status(204).end()
}))

o.post('/documents/delete-decision', member('member'), h(async (req, res) => {
  const b = idList.extend({ approved: z.boolean() }).parse(req.body)
  const docs = await Doc.find({ org: orgOf(req), _id: { $in: b.ids }, deleteRequestedAt: { $ne: null } })
  if (!docs.length) throw new HttpError(404, 'Deletion request not found.')
  for (const d of docs) {
    const folder = await Folder.findById(d.folder).select('access')
    if (req.role !== 'owner' && !folderPermission(folder ?? {}, req, 'manage')) throw new HttpError(403, 'Only folder managers can decide this request.')
  }
  await Doc.updateMany({ _id: { $in: docs.map((d) => d._id) } }, b.approved ? { trashed: true, $unset: { deleteRequestedBy: 1, deleteRequestedAt: 1 } } : { $unset: { deleteRequestedBy: 1, deleteRequestedAt: 1 } })
  res.status(204).end()
}))

o.delete('/documents', member('admin'), h(async (req, res) => {
  const { ids } = idList.parse(req.body)
  const docs = await Doc.find({ org: orgOf(req), _id: { $in: ids }, trashed: true })
  for (const d of docs) {
    const folder = await Folder.findById(d.folder).select('access')
    if (req.role !== 'owner' && !folderPermission(folder ?? {}, req, 'manage')) throw new HttpError(403, 'Only folder managers can permanently delete files in this folder.')
  }
  await Promise.all(docs.map((d) => del(d.key)))
  await Doc.deleteMany({ _id: { $in: docs.map((d) => d._id) } })
  await audit(orgOf(req), req.uid!, 'document.purge', `${docs.length} file(s)`)
  res.status(204).end()
}))

o.get('/documents/:id', member('member'), h(async (req, res) => {
  const d = await Doc.findOne({ _id: oid.parse(req.params.id), org: orgOf(req), trashed: false }).populate('owner', 'name').lean<DocLean>()
  if (!d) throw new HttpError(404, 'Document not found.')
  const allowed = req.role === 'owner' || (await visibleFolderIds(req)).some((id) => String(id) === String(d.folder))
  if (!allowed) throw new HttpError(404, 'Document not found.')
  const folder = await Folder.findById(d.folder).select('name').lean()
  res.json({ ...dto(d, req.uid!), folderName: folder?.name ?? 'Unsorted', mime: d.mime ?? null, created: d.createdAt, deleteRequested: !!d.deleteRequestedAt })
}))

o.post('/documents/copy', member('member'), h(async (req, res) => {
  const b = z.object({ ids: z.array(oid).min(1).max(20), folderId: oid }).parse(req.body)
  const target = await Folder.findOne({ _id: b.folderId, org: orgOf(req) }).select('access')
  if (!target || (req.role !== 'owner' && !folderPermission(target, req, 'upload'))) throw new HttpError(403, 'You do not have access to copy files into this folder.')
  const docs = await Doc.find({ org: orgOf(req), _id: { $in: b.ids }, trashed: false }).lean()
  for (const d of docs) {
    const source = await Folder.findById(d.folder).select('access')
    if (!source || (req.role !== 'owner' && !folderPermission(source, req, 'view'))) continue
    const key = `${orgOf(req)}/${randomUUID()}`
    await copy(d.key, key, d.mime)
    await Doc.create({ org: orgOf(req), folder: b.folderId, owner: req.uid, name: d.name, key, mime: d.mime, size: d.size })
  }
  res.status(204).end()
}))

o.post('/documents/move', member('member'), h(async (req, res) => {
  const b = z.object({ ids: z.array(oid).min(1).max(20), folderId: oid }).parse(req.body)
  const target = await Folder.findOne({ _id: b.folderId, org: orgOf(req) }).select('access')
  if (!target || (req.role !== 'owner' && !folderPermission(target, req, 'upload'))) throw new HttpError(403, 'You do not have access to move files into this folder.')
  const docs = await Doc.find({ org: orgOf(req), _id: { $in: b.ids }, trashed: false })
  for (const d of docs) {
    const source = await Folder.findById(d.folder).select('access')
    if (!source || (req.role !== 'owner' && !folderPermission(source, req, 'edit'))) continue
    d.folder = b.folderId
    await d.save()
  }
  res.status(204).end()
}))

o.get('/documents/:id/download', member('member'), h(async (req, res) => {
  const d = oid.safeParse(req.params.id).success ? await Doc.findOne({ _id: req.params.id, org: orgOf(req), trashed: false }) : null
  if (!d) throw new HttpError(404, 'Document not found.')
  res.json({ url: await signedGet(d.key, d.name, req.query.inline === '1') })
}))

// ---------- activity ----------
o.get('/activity', member('admin'), h(async (req, res) => {
  const items = await Audit.find({ org: orgOf(req) }).sort({ createdAt: -1 }).limit(50).populate<{ actor: { name: string } }>('actor', 'name').lean()
  res.json({ items: items.map((a) => ({ id: String(a._id), actor: a.actor?.name ?? 'Former member', action: a.action, detail: a.detail ?? '', at: a.createdAt })) })
}))

// ---------- people and invitations ----------
o.get('/members', member('member'), h(async (req, res) => {
  const org = orgOf(req)
  const isAdmin = req.role !== 'member'
  const ms = await Membership.find({ org }).sort({ createdAt: 1 }).populate<{ user: { _id: Types.ObjectId; name: string; username: string; email: string } }>('user', 'name username email').lean()
  const invites = isAdmin ? await Invite.find({ org, acceptedAt: null, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).lean() : []
  res.json({
    members: ms.map((m) => ({ id: String(m.user._id), name: m.user.name, username: m.user.username, email: isAdmin ? m.user.email : undefined, role: m.role })),
    invites: invites.map((i) => ({ id: String(i._id), to: i.username ? `@${i.username}` : i.email, role: i.role, expires: i.expiresAt })),
  })
}))

o.get('/member-search', member('admin'), h(async (req, res) => {
  const q = z.string().trim().toLowerCase().min(2).max(80).parse(req.query.q)
  const users = await User.find({ $or: [{ email: { $regex: q, $options: 'i' } }, { username: { $regex: q, $options: 'i' } }], _id: { $nin: await Membership.find({ org: orgOf(req) }).distinct('user') } })
    .select('name username email').limit(8).lean()
  res.json({ items: users.map((u) => ({ name: u.name, username: u.username, email: u.email })) })
}))

o.get('/requests', member('admin'), h(async (req, res) => {
  const items = await JoinRequest.find({ org: orgOf(req), status: 'pending' }).populate<{ user: { name: string; username: string } }>('user', 'name username').lean()
  res.json({ items: items.map((i) => ({ id: String(i._id), userId: String(i.user._id), name: i.user.name, username: i.user.username, createdAt: i.createdAt })) })
}))

o.patch('/requests/:id', member('admin'), h(async (req, res) => {
  const { status } = z.object({ status: z.enum(['approved', 'rejected']) }).parse(req.body)
  const request = await JoinRequest.findOne({ _id: oid.parse(req.params.id), org: orgOf(req), status: 'pending' })
  if (!request) throw new HttpError(404, 'Join request not found.')
  if (status === 'approved') await Membership.updateOne({ org: request.org, user: request.user }, { $setOnInsert: { role: 'member' } }, { upsert: true })
  request.status = status
  await request.save()
  await notify([request.user], orgOf(req), status === 'approved' ? 'Your request to join the workspace was approved.' : 'Your request to join the workspace was declined.')
  res.status(204).end()
}))

o.post('/invites', member('admin'), h(async (req, res) => {
  const b = z.object({
    email: z.string().trim().toLowerCase().email().optional(),
    username: z.string().trim().toLowerCase().regex(/^@?[a-z0-9_]{3,20}$/, 'Enter a valid username.').optional(),
    role: z.enum(['admin', 'member']).default('member'),
  }).parse(req.body)
  if (!!b.email === !!b.username) throw new HttpError(400, 'Enter an email or a username.')
  const target = b.username ? await User.findOne({ username: b.username.replace(/^@/, '') }) : null
  if (b.username && !target) throw new HttpError(404, 'No one has that username.')
  const email = target ? target.email : b.email!
  const label = target ? `@${target.username}` : email
  if (b.role === 'admin' && !['owner', 'admin'].includes(req.role!)) throw new HttpError(403, 'Only an admin can invite admins.')
  const org = orgOf(req)
  const existing = target ?? (await User.findOne({ email }))
  const portalTarget = target ?? existing
  if (portalTarget && (await Membership.exists({ org, user: portalTarget._id }))) throw new HttpError(409, 'This person is already a member.')
  await Invite.deleteMany({ org, email, acceptedAt: null })
  const token = randomBytes(32).toString('hex')
  const inv = await Invite.create({ org, email, username: portalTarget?.username, role: b.role, tokenHash: sha(token), invitedBy: req.uid, expiresAt: new Date(Date.now() + 7 * 864e5) })
  const [orgDoc, inviter] = await Promise.all([Org.findById(org), User.findById(req.uid)])
  if (portalTarget) {
    const invitationText = `${inviter?.name ?? 'An admin'} invited you to join ${orgDoc?.name ?? 'a workspace'} as an ${b.role === 'admin' ? 'admin' : 'member'}`
    await notify([portalTarget._id], org, invitationText)
    const personalMemberships = await Membership.find({ user: portalTarget._id, role: 'owner' })
      .populate<{ org: { _id: Types.ObjectId; personal?: boolean } }>('org', 'personal').lean()
    const personalMembership = personalMemberships.find((m) => m.org.personal)
    if (personalMembership) await notify([portalTarget._id], personalMembership.org._id, invitationText)
    const link = `${env.CLIENT_URL}/invite/${token}`
    let emailSent = true
    try {
      const { error } = await resend.emails.send({
        from: env.MAIL_FROM, to: portalTarget.email,
        subject: `${inviter?.name ?? 'Someone'} invited you to ${orgDoc?.name ?? 'a workspace'} on OrbitDocs`,
        html: `<div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;padding:24px;color:#0f172a">
          <h2 style="margin:0 0 12px">Join ${esc(orgDoc?.name ?? 'the workspace')}</h2>
          <p style="color:#475569;line-height:1.6">${esc(inviter?.name ?? 'A teammate')} invited you to collaborate on documents in OrbitDocs.</p>
          <p><a href="${link}" style="display:inline-block;background:#287bff;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">Accept invitation</a></p>
          <p style="color:#94a3b8;font-size:13px">This invitation is also available in your OrbitDocs notifications.</p></div>`,
      })
      emailSent = !error
    } catch {
      emailSent = false
    }
    await audit(org, req.uid!, 'invite.send', label)
    return res.status(201).json({ id: inv.id, to: label, role: inv.role, expires: inv.expiresAt, emailSent })
  }
  const link = `${env.CLIENT_URL}/invite/${token}`
  const { error } = await resend.emails.send({
    from: env.MAIL_FROM, to: email,
    subject: `${inviter?.name ?? 'Someone'} invited you to ${orgDoc?.name ?? 'a workspace'} on OrbitDocs`,
    html: `<div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;padding:24px;color:#0f172a">
      <h2 style="margin:0 0 12px">Join ${esc(orgDoc?.name ?? 'the workspace')}</h2>
      <p style="color:#475569;line-height:1.6">${esc(inviter?.name ?? 'A teammate')} invited you to collaborate on documents in OrbitDocs.</p>
      <p><a href="${link}" style="display:inline-block;background:#287bff;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">Accept invitation</a></p>
      <p style="color:#94a3b8;font-size:13px">This link expires in 7 days. If you were not expecting it, you can ignore this email.</p></div>`,
  })
  if (error) { await inv.deleteOne(); throw new HttpError(502, 'We could not send the invitation email. Check the address and try again.') }
  await audit(org, req.uid!, 'invite.send', label)
  res.status(201).json({ id: inv.id, to: label, role: inv.role, expires: inv.expiresAt })
}))

o.delete('/invites/:id', member('admin'), h(async (req, res) => {
  const id = oid.parse(req.params.id)
  await Invite.deleteOne({ _id: id, org: orgOf(req), acceptedAt: null })
  await audit(orgOf(req), req.uid!, 'invite.revoke')
  res.status(204).end()
}))

o.patch('/members/:userId', member('admin'), h(async (req, res) => {
  const userId = oid.parse(req.params.userId)
  const { role } = z.object({ role: z.enum(['admin', 'member']) }).parse(req.body)
  const m = await Membership.findOne({ org: orgOf(req), user: userId })
  if (!m) throw new HttpError(404, 'Member not found.')
  if (m.role === 'owner' || (m.role === 'admin' && req.role !== 'owner' && role !== 'admin')) throw new HttpError(403, 'Only the owner can change an admin role.')
  m.role = role
  await m.save()
  const target = await User.findById(userId).select('name')
  await audit(orgOf(req), req.uid!, 'member.role', `${target?.name ?? 'A member'} is now ${role}`)
  res.status(204).end()
}))

o.delete('/members/:userId', member('admin'), h(async (req, res) => {
  const userId = oid.parse(req.params.userId)
  const m = await Membership.findOne({ org: orgOf(req), user: userId })
  if (!m) throw new HttpError(404, 'Member not found.')
  if (m.role === 'owner') throw new HttpError(400, 'The owner cannot be removed.')
  if (m.role === 'admin' && req.role !== 'owner') throw new HttpError(403, 'Only the owner can remove admins.')
  const target = await User.findById(userId).select('name')
  await m.deleteOne()
  await audit(orgOf(req), req.uid!, 'member.remove', target?.name ?? 'A member')
  res.status(204).end()
}))

o.post('/leave', member('member'), h(async (req, res) => {
  if (req.role === 'owner') throw new HttpError(409, 'The organization owner cannot leave. Transfer ownership or delete the organization.')
  const org = orgOf(req)
  const user = await User.findById(req.uid).select('name')
  await Membership.deleteOne({ org, user: req.uid })
  await audit(org, req.uid!, 'member.leave', user?.name ?? 'A member')
  const admins = await Membership.find({ org, role: { $in: ['owner', 'admin'] } }).select('user').lean()
  await notify(admins.map((m) => m.user), org, `${user?.name ?? 'A member'} left the organization`)
  res.status(204).end()
}))

o.get('/usage', member('member'), h(async (req, res) => {
  const org = orgOf(req)
  const [used, quota, cfg] = await Promise.all([usedBytes(org), orgQuota(org), getSettings()])
  res.json({ used, quota, maxFileBytes: cfg.maxFileMB * MB })
}))

// Shareable join links. Anyone with a valid link can join as a member until it expires, is used up, or is revoked.
o.get('/links', member('admin'), h(async (req, res) => {
  const items = await JoinLink.find({ org: orgOf(req), revoked: false, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).lean()
  res.json({ items: items.map((l) => ({ id: String(l._id), url: `${env.CLIENT_URL}/join/${l.token}`, expires: l.expiresAt, uses: l.uses, maxUses: l.maxUses ?? null })) })
}))

o.post('/links', member('admin'), h(async (req, res) => {
  const b = z.object({ days: z.number().int().min(1).max(30).default(7), maxUses: z.number().int().min(1).max(500).optional() }).parse(req.body)
  const l = await JoinLink.create({ org: orgOf(req), createdBy: req.uid, token: randomBytes(24).toString('hex'), expiresAt: new Date(Date.now() + b.days * 864e5), maxUses: b.maxUses })
  await audit(orgOf(req), req.uid!, 'link.create', `${b.days} days`)
  res.status(201).json({ id: l.id, url: `${env.CLIENT_URL}/join/${l.token}`, expires: l.expiresAt, uses: 0, maxUses: l.maxUses ?? null })
}))

o.delete('/links/:id', member('admin'), h(async (req, res) => {
  await JoinLink.updateOne({ _id: oid.parse(req.params.id), org: orgOf(req) }, { revoked: true })
  await audit(orgOf(req), req.uid!, 'link.revoke')
  res.status(204).end()
}))

const validLink = (token: string) => ({
  token, revoked: false, expiresAt: { $gt: new Date() },
  $or: [{ maxUses: null }, { $expr: { $lt: ['$uses', '$maxUses'] } }],
})

r.get('/join/:token', authLimit, h(async (req, res) => {
  const l = await JoinLink.findOne(validLink(tokenParam.parse(req.params.token))).populate<{ org: { name: string; suspended?: boolean } }>('org', 'name suspended')
  if (!l || l.org.suspended) throw new HttpError(404, 'This link is no longer valid.')
  res.json({ orgName: l.org.name })
}))

r.post('/join/:token', authLimit, auth, h(async (req, res) => {
  const l = await JoinLink.findOneAndUpdate(validLink(tokenParam.parse(req.params.token)), { $inc: { uses: 1 } })
  if (!l) throw new HttpError(404, 'This link is no longer valid.')
  if (await Org.exists({ _id: l.org, suspended: true })) throw new HttpError(403, 'This workspace has been suspended.')
  if (await Membership.exists({ user: req.uid, org: l.org })) {
    await JoinLink.updateOne({ _id: l._id }, { $inc: { uses: -1 } })
    return res.json({ orgId: String(l.org) })
  }
  const u = await User.findById(req.uid)
  await Membership.create({ user: req.uid, org: l.org, role: 'member' })
  const admins = await Membership.find({ org: l.org, role: { $in: ['owner', 'admin'] }, user: { $ne: new Types.ObjectId(req.uid!) } }).select('user').lean()
  const joined = await User.findById(req.uid).select('name username')
  await notify(admins.map((m) => m.user), l.org, `${joined?.name ?? 'A member'} joined the workspace`)
  await audit(l.org, req.uid!, 'link.join', u ? `@${u.username}` : '')
  res.json({ orgId: String(l.org) })
}))

r.get('/invites/mine', auth, h(async (req, res) => {
  const u = await User.findById(req.uid)
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  const items = await Invite.find({ email: u.email, acceptedAt: null, expiresAt: { $gt: new Date() } }).populate<{ org: { name: string } }>('org', 'name').lean()
  res.json({ items: items.map((i) => ({ id: String(i._id), orgName: i.org.name, role: i.role, expires: i.expiresAt })) })
}))

r.post('/invites/mine/:id/accept', auth, h(async (req, res) => {
  const u = await User.findById(req.uid)
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  const i = await Invite.findOne({ _id: oid.parse(req.params.id), email: u.email, acceptedAt: null, expiresAt: { $gt: new Date() } })
  if (!i) throw new HttpError(404, 'This invitation is not valid.')
  if (await Org.exists({ _id: i.org, suspended: true })) throw new HttpError(403, 'This workspace has been suspended.')
  if (!u.emailVerified) { u.emailVerified = true; await u.save() }
  await Membership.updateOne({ user: u._id, org: i.org }, { $setOnInsert: { role: i.role } }, { upsert: true })
  i.acceptedAt = new Date()
  await i.save()
  await audit(i.org, u.id, 'invite.accept', `@${u.username}`)
  await notify([i.invitedBy], i.org, `${u.name} accepted your invitation`)
  res.json({ orgId: String(i.org) })
}))

const tokenParam = z.string().min(20).max(100)
async function findInvite(token: string) {
  const i = await Invite.findOne({ tokenHash: sha(token) }).populate<{ org: { _id: Types.ObjectId; name: string } }>('org', 'name')
  if (!i || i.acceptedAt) throw new HttpError(404, 'This invitation is not valid.')
  if (i.expiresAt < new Date()) throw new HttpError(410, 'This invitation has expired. Ask for a new one.')
  return i
}

r.get('/invites/:token', authLimit, h(async (req, res) => {
  const i = await findInvite(tokenParam.parse(req.params.token))
  res.json({ orgName: i.org.name, email: i.email, role: i.role, hasAccount: !!(await User.exists({ email: i.email })) })
}))

// The signed-in account must match the invited email, so a forwarded link cannot be used by someone else.
r.post('/invites/:token/accept', auth, h(async (req, res) => {
  const i = await findInvite(tokenParam.parse(req.params.token))
  const u = await User.findById(req.uid)
  if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
  if (u.email !== i.email) throw new HttpError(403, `This invitation was sent to ${i.email}. Sign in with that address.`)
  if (!u.emailVerified) { u.emailVerified = true; await u.save() } // they received the link at this address
  await Membership.updateOne({ user: u._id, org: i.org._id }, { $setOnInsert: { role: i.role } }, { upsert: true })
  i.acceptedAt = new Date()
  await i.save()
  await audit(i.org._id, u.id, 'invite.accept', `@${u.username}`)
  await notify([i.invitedBy], i.org._id, `${u.name} accepted your invitation`)
  res.json({ orgId: String(i.org._id) })
}))

export default r
