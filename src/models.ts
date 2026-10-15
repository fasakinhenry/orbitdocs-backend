import { Schema, model, Types } from 'mongoose'

const ref = (to: string) => ({ type: Schema.Types.ObjectId, ref: to, required: true })

export const User = model('User', new Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  suspended: { type: Boolean, default: false },
  emailVerified: { type: Boolean, default: false },
  avatarKey: String,
  bio: { type: String, default: '' },
  socialLinks: { type: Map, of: String, default: {} },
  profilePublic: { type: Boolean, default: true },
  passwordChangedAt: Date,
}, { timestamps: true }))

export const Org = model('Org', new Schema({
  name: { type: String, required: true, trim: true },
  slug: { type: String, required: true, unique: true },
  type: { type: String, required: true },
  description: { type: String, default: '' },
  logoKey: String,
  suspended: { type: Boolean, default: false },
  quotaBytes: Number,
  visibility: { type: String, enum: ['public', 'private'], default: 'public' },
  personal: { type: Boolean, default: false },
}, { timestamps: true }))

export const ROLES = ['member', 'admin', 'owner'] as const
export type Role = (typeof ROLES)[number]

const membership = new Schema({
  user: ref('User'), org: ref('Org'),
  role: { type: String, enum: ROLES, default: 'member' },
}, { timestamps: true })
membership.index({ user: 1, org: 1 }, { unique: true })
export const Membership = model('Membership', membership)

export const Folder = model('Folder', new Schema({
  org: ref('Org'),
  name: { type: String, required: true, trim: true },
  access: [{
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    view: { type: Boolean, default: true },
    upload: { type: Boolean, default: false },
    edit: { type: Boolean, default: false },
    delete: { type: Boolean, default: false },
  }],
}, { timestamps: true }))

const doc = new Schema({
  org: ref('Org'), folder: ref('Folder'), owner: ref('User'),
  name: { type: String, required: true },
  key: { type: String, required: true },
  mime: String,
  size: { type: Number, required: true },
  status: { type: String, enum: ['draft', 'pending', 'approved'], default: 'draft' },
  starredBy: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  trashed: { type: Boolean, default: false },
}, { timestamps: true })
doc.index({ org: 1, trashed: 1, updatedAt: -1 })
export const Doc = model('Doc', doc)

const invite = new Schema({
  org: ref('Org'), invitedBy: ref('User'),
  email: { type: String, required: true, lowercase: true, trim: true },
  role: { type: String, enum: ['admin', 'member'], default: 'member' },
  tokenHash: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
  acceptedAt: Date,
  username: String,
}, { timestamps: true })
invite.index({ org: 1, email: 1 })
export const Invite = model('Invite', invite)

export const Audit = model('Audit', new Schema({
  org: ref('Org'), actor: ref('User'),
  action: { type: String, required: true },
  detail: String,
}, { timestamps: { createdAt: true, updatedAt: false } }))

const token = new Schema({
  user: ref('User'),
  kind: { type: String, enum: ['verify', 'reset'], required: true },
  tokenHash: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
  usedAt: Date,
}, { timestamps: true })
token.index({ expiresAt: 1 }, { expireAfterSeconds: 86400 })
export const Token = model('Token', token)

const note = new Schema({
  user: ref('User'), org: ref('Org'),
  text: { type: String, required: true },
  readAt: Date,
}, { timestamps: { createdAt: true, updatedAt: false } })
note.index({ user: 1, org: 1, createdAt: -1 })
note.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 86400 })
export const Note = model('Note', note)

export const JoinLink = model('JoinLink', new Schema({
  org: ref('Org'), createdBy: ref('User'),
  token: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
  maxUses: Number,
  uses: { type: Number, default: 0 },
  revoked: { type: Boolean, default: false },
}, { timestamps: true }))

export const JoinRequest = model('JoinRequest', new Schema({
  org: ref('Org'), user: ref('User'),
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
}, { timestamps: true }))

export const Settings = model('Settings', new Schema({
  key: { type: String, default: 'platform', unique: true },
  defaultQuotaMB: { type: Number, default: 200 },
  maxFileMB: { type: Number, default: 25 },
  registrationOpen: { type: Boolean, default: true },
}))

export const AdminLog = model('AdminLog', new Schema({
  actor: ref('User'),
  action: { type: String, required: true },
  detail: String,
}, { timestamps: { createdAt: true, updatedAt: false } }))

export type Oid = Types.ObjectId
