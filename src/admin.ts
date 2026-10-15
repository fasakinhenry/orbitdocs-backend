import { Router, type RequestHandler } from 'express'
import jwt from 'jsonwebtoken'
import { z } from 'zod'
import { Types } from 'mongoose'
import { env } from './config'
import { AdminLog, Audit, Doc, Folder, Invite, JoinLink, Membership, Note, Org, Settings, Token, User } from './models'
import { del, h, HttpError } from './lib'
import { MB, getSettings } from './platform'
import { storageInfo } from './storage'

const a = Router()
const oid = z.string().regex(/^[a-f\d]{24}$/i)
const rx = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const page = z.object({ q: z.string().max(80).optional(), page: z.coerce.number().int().min(1).default(1) })
const PER = 20

// Platform admin only. Anyone else, signed in or not, gets the same 404 as a route that does not exist.
const adminOnly: RequestHandler = async (req, _res, next) => {
  try {
    const t = req.headers.authorization?.replace(/^Bearer /, '')
    const uid = (jwt.verify(t ?? '', env.JWT_ACCESS_SECRET) as { sub: string }).sub
    const u = await User.findById(uid).select('email emailVerified').lean()
    if (!u || !u.emailVerified || u.email !== env.ADMIN_EMAIL.toLowerCase()) throw new Error('not admin')
    req.uid = uid
    next()
  } catch { next(new HttpError(404, 'Not found.')) }
}
a.use(adminOnly)

const record = (req: { uid?: string }, action: string, detail?: string) => AdminLog.create({ actor: req.uid, action, detail })
async function removeKeys(keys: string[]) {
  for (let i = 0; i < keys.length; i += 25) await Promise.allSettled(keys.slice(i, i + 25).map((k) => del(k)))
}

const days = Array.from({ length: 7 }, (_, i) => new Date(Date.now() - (6 - i) * 864e5).toISOString().slice(0, 10))
const fill = (rows: { _id: string; n: number }[]) => days.map((day) => ({ day, n: rows.find((r) => r._id === day)?.n ?? 0 }))
const perDay = { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, n: { $sum: 1 } } }

a.get('/stats', h(async (_req, res) => {
  const since = { $match: { createdAt: { $gte: new Date(Date.now() - 7 * 864e5) } } }
  const [users, orgs, files, bytes, signups, uploads, top, settings] = await Promise.all([
    User.countDocuments(), Org.countDocuments(), Doc.countDocuments(),
    Doc.aggregate<{ b: number }>([{ $group: { _id: null, b: { $sum: '$size' } } }]),
    User.aggregate<{ _id: string; n: number }>([since, perDay]),
    Doc.aggregate<{ _id: string; n: number }>([since, perDay]),
    Doc.aggregate<{ _id: Types.ObjectId; b: number }>([{ $group: { _id: '$org', b: { $sum: '$size' } } }, { $sort: { b: -1 } }, { $limit: 5 }]),
    getSettings(),
  ])
  const names = await Org.find({ _id: { $in: top.map((t) => t._id) } }).select('name').lean()
  res.json({
    users, orgs, files, bytes: bytes[0]?.b ?? 0, signups: fill(signups), uploads: fill(uploads),
    top: top.map((t) => ({ id: String(t._id), name: names.find((n) => String(n._id) === String(t._id))?.name ?? 'Deleted workspace', bytes: t.b })),
    storage: storageInfo, settings,
  })
}))

// ---------- workspaces ----------
a.get('/orgs', h(async (req, res) => {
  const q = page.parse(req.query)
  const f = q.q ? { name: { $regex: rx(q.q), $options: 'i' } } : {}
  const [orgs, total, s] = await Promise.all([
    Org.find(f).sort({ createdAt: -1 }).skip((q.page - 1) * PER).limit(PER).lean(), Org.countDocuments(f), getSettings(),
  ])
  const ids = orgs.map((o) => o._id)
  const [mem, files, owners] = await Promise.all([
    Membership.aggregate<{ _id: Types.ObjectId; n: number }>([{ $match: { org: { $in: ids } } }, { $group: { _id: '$org', n: { $sum: 1 } } }]),
    Doc.aggregate<{ _id: Types.ObjectId; n: number; b: number }>([{ $match: { org: { $in: ids } } }, { $group: { _id: '$org', n: { $sum: 1 }, b: { $sum: '$size' } } }]),
    Membership.find({ org: { $in: ids }, role: 'owner' }).populate<{ user: { name: string; email: string; username: string } }>('user', 'name email username').lean(),
  ])
  const same = (x: Types.ObjectId, y: Types.ObjectId) => String(x) === String(y)
  res.json({
    total,
    items: orgs.map((o) => {
      const d = files.find((x) => same(x._id, o._id))
      const ow = owners.find((x) => same(x.org, o._id))
      return {
        id: String(o._id), name: o.name, slug: o.slug, type: o.type, createdAt: o.createdAt, suspended: !!o.suspended,
        members: mem.find((x) => same(x._id, o._id))?.n ?? 0, files: d?.n ?? 0, bytes: d?.b ?? 0,
        quotaBytes: o.quotaBytes ?? s.defaultQuotaMB * MB, customQuota: o.quotaBytes != null,
        owner: ow ? { name: ow.user.name, email: ow.user.email, username: ow.user.username } : null,
      }
    }),
  })
}))

a.patch('/orgs/:id', h(async (req, res) => {
  const id = oid.parse(req.params.id)
  const b = z.object({ suspended: z.boolean().optional(), quotaMB: z.number().int().min(1).max(1_000_000).nullable().optional() }).parse(req.body)
  const update: Record<string, unknown> = {}
  if (b.suspended !== undefined) update.suspended = b.suspended
  const op: Record<string, unknown> = Object.keys(update).length ? { $set: update } : {}
  if (b.quotaMB === null) op.$unset = { quotaBytes: 1 }
  else if (b.quotaMB !== undefined) op.$set = { ...update, quotaBytes: b.quotaMB * MB }
  if (!(await Org.findByIdAndUpdate(id, op))) throw new HttpError(404, 'Workspace not found.')
  await record(req, 'org.update', `${id} ${JSON.stringify(b)}`)
  res.status(204).end()
}))

a.delete('/orgs/:id', h(async (req, res) => {
  const id = new Types.ObjectId(oid.parse(req.params.id))
  const org = await Org.findById(id)
  if (!org) throw new HttpError(404, 'Workspace not found.')
  const docs = await Doc.find({ org: id }).select('key').lean()
  await removeKeys([...docs.map((d) => d.key), ...(org.logoKey ? [org.logoKey] : [])])
  await Promise.all([Doc, Folder, Membership, Invite, JoinLink, Note, Audit].map((m) => (m as typeof Doc).deleteMany({ org: id })))
  await org.deleteOne()
  await record(req, 'org.delete', org.name)
  res.status(204).end()
}))

// ---------- users ----------
a.get('/users', h(async (req, res) => {
  const q = page.parse(req.query)
  const r = q.q ? { $regex: rx(q.q), $options: 'i' } : null
  const f = r ? { $or: [{ name: r }, { email: r }, { username: r }] } : {}
  const [users, total] = await Promise.all([
    User.find(f).sort({ createdAt: -1 }).skip((q.page - 1) * PER).limit(PER).select('-passwordHash').lean(), User.countDocuments(f),
  ])
  const counts = await Membership.aggregate<{ _id: Types.ObjectId; n: number }>([{ $match: { user: { $in: users.map((u) => u._id) } } }, { $group: { _id: '$user', n: { $sum: 1 } } }])
  res.json({
    total,
    items: users.map((u) => ({
      id: String(u._id), name: u.name, username: u.username, email: u.email, emailVerified: !!u.emailVerified,
      suspended: !!u.suspended, createdAt: u.createdAt, workspaces: counts.find((c) => String(c._id) === String(u._id))?.n ?? 0,
    })),
  })
}))

a.patch('/users/:id', h(async (req, res) => {
  const id = oid.parse(req.params.id)
  const b = z.object({ suspended: z.boolean().optional(), emailVerified: z.boolean().optional() }).parse(req.body)
  if (id === req.uid && b.suspended) throw new HttpError(400, 'You cannot suspend your own account.')
  if (!(await User.findByIdAndUpdate(id, b))) throw new HttpError(404, 'User not found.')
  await record(req, 'user.update', `${id} ${JSON.stringify(b)}`)
  res.status(204).end()
}))

a.delete('/users/:id', h(async (req, res) => {
  const id = new Types.ObjectId(oid.parse(req.params.id))
  if (String(id) === req.uid) throw new HttpError(400, 'You cannot delete your own account.')
  const u = await User.findById(id)
  if (!u) throw new HttpError(404, 'User not found.')
  if (await Membership.exists({ user: id, role: 'owner' })) throw new HttpError(409, 'This user owns a workspace. Delete or suspend the workspace first.')
  await Promise.all([Membership.deleteMany({ user: id }), Token.deleteMany({ user: id }), Note.deleteMany({ user: id }), Invite.deleteMany({ email: u.email })])
  await u.deleteOne()
  await record(req, 'user.delete', `@${u.username}`)
  res.status(204).end()
}))

// ---------- platform settings and log ----------
a.get('/settings', h(async (_req, res) => { res.json(await getSettings()) }))

a.patch('/settings', h(async (req, res) => {
  const b = z.object({
    defaultQuotaMB: z.number().int().min(1).max(1_000_000), maxFileMB: z.number().int().min(1).max(50), registrationOpen: z.boolean(),
  }).parse(req.body)
  await getSettings()
  await Settings.updateOne({ key: 'platform' }, b)
  await record(req, 'settings.update', JSON.stringify(b))
  res.json(await getSettings())
}))

a.get('/log', h(async (_req, res) => {
  const items = await AdminLog.find().sort({ createdAt: -1 }).limit(100).lean()
  res.json({ items: items.map((l) => ({ id: String(l._id), action: l.action, detail: l.detail ?? '', at: l.createdAt })) })
}))

export default a
