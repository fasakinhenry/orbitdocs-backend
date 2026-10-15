import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import request from 'supertest'
import mongoose from 'mongoose'
import { MongoMemoryServer } from 'mongodb-memory-server'

type Mail = { to: string; html: string; subject: string }
const mail = vi.hoisted(() => ({ sent: [] as Mail[] }))
vi.mock('resend', () => ({
  Resend: class { emails = { send: async (m: Mail) => { mail.sent.push(m); return { error: null } } } },
}))
vi.mock('../src/lib', async (orig) => ({
  ...(await orig<typeof import('../src/lib')>()),
  put: vi.fn(async () => undefined),
  del: vi.fn(async () => undefined),
  signedGet: vi.fn(async (k: string) => `https://signed.test/${k}`),
}))

import { app } from '../src/app'
import { Invite } from '../src/models'

const http = request(app)
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` })
const PASSWORD = 'password123'

function tokenFrom(to: string, kind: 'verify' | 'reset' | 'invite') {
  const m = [...mail.sent].reverse().find((e) => e.to === to && e.html.includes(`/${kind}/`))
  return new RegExp(`/${kind}/([a-f0-9]{64})`).exec(m!.html)![1]
}
async function register(name: string, email: string) {
  const r = await http.post('/api/auth/register').send({ name, username: name.toLowerCase(), email, password: PASSWORD })
  expect(r.status).toBe(201)
  return r.body.accessToken as string
}
async function verify(email: string) {
  expect((await http.post('/api/auth/verify').send({ token: tokenFrom(email, 'verify') })).status).toBe(204)
}
const newOrg = (t: string, slug: string) =>
  http.post('/api/orgs').set(bearer(t)).send({ name: slug, slug, type: 'Startup', description: '' })

const run = process.env.RUN_DB_TESTS ? describe : describe.skip

run('full workflow (in-memory MongoDB)', () => {
  let mongod: MongoMemoryServer
  let A = '', B = '', C = '', org = '', folder = '', docId = ''

  beforeAll(async () => {
    mongod = await MongoMemoryServer.create()
    await mongoose.connect(mongod.getUri())
  })
  afterAll(async () => { await mongoose.disconnect(); await mongod?.stop() })

  it('blocks workspace creation until the email is verified', async () => {
    A = await register('Ada', 'ada@example.com')
    expect((await newOrg(A, 'acme')).status).toBe(403)
  })

  it('verifies the email and makes the creator the owner with starter folders', async () => {
    await verify('ada@example.com')
    const r = await newOrg(A, 'acme')
    expect(r.status).toBe(201)
    org = r.body.id
    const me = await http.get('/api/auth/me').set(bearer(A))
    expect(me.body.organizations[0].role).toBe('owner')
    const f = await http.get(`/api/orgs/${org}/folders`).set(bearer(A))
    expect(f.body.items).toHaveLength(7)
    folder = f.body.items[0].id
  })

  it('invites a member who joins with the invited address, without a duplicate account', async () => {
    B = await register('Ben', 'ben@example.com')
    const inv = await http.post(`/api/orgs/${org}/invites`).set(bearer(A)).send({ email: 'ben@example.com', role: 'member' })
    expect(inv.status).toBe(201)
    const token = tokenFrom('ben@example.com', 'invite')
    const preview = await http.get(`/api/invites/${token}`)
    expect(preview.body.hasAccount).toBe(true)
    expect((await http.post(`/api/invites/${token}/accept`).set(bearer(A))).status).toBe(403)
    expect((await http.post(`/api/invites/${token}/accept`).set(bearer(B))).status).toBe(200)
    const me = await http.get('/api/auth/me').set(bearer(B))
    expect(me.body.organizations[0].role).toBe('member')
    expect(me.body.user.emailVerified).toBe(true)
    expect((await http.get(`/api/invites/${token}`)).status).toBe(404)
  })

  it('lets members upload but not trash', async () => {
    const up = await http.post(`/api/orgs/${org}/documents`).set(bearer(B)).field('folderId', folder).attach('files', Buffer.from('hello'), 'notes.pdf')
    expect(up.status).toBe(201)
    expect(up.body.items[0].status).toBe('draft')
    docId = up.body.items[0].id
    const trash = await http.post(`/api/orgs/${org}/documents/trash`).set(bearer(B)).send({ ids: [docId] })
    expect(trash.status).toBe(403)
  })

  it('notifies admins on submit and the owner on approval, and records both', async () => {
    expect((await http.post(`/api/orgs/${org}/documents/submit`).set(bearer(B)).send({ ids: [docId] })).status).toBe(204)
    const a = await http.get(`/api/orgs/${org}/notifications`).set(bearer(A))
    expect(a.body.unread).toBe(1)
    expect(a.body.items[0].text).toContain('submitted')
    expect((await http.post(`/api/orgs/${org}/documents/status`).set(bearer(A)).send({ ids: [docId], status: 'approved' })).status).toBe(204)
    const b = await http.get(`/api/orgs/${org}/notifications`).set(bearer(B))
    expect(b.body.items.some((n: { text: string }) => n.text.includes('approved'))).toBe(true)
    const act = await http.get(`/api/orgs/${org}/activity`).set(bearer(A))
    expect(act.body.items.map((i: { action: string }) => i.action)).toEqual(expect.arrayContaining(['document.upload', 'document.approved']))
    expect((await http.get(`/api/orgs/${org}/activity`).set(bearer(B))).status).toBe(403)
  })

  it('lets members search and download permitted documents', async () => {
    const list = await http.get(`/api/orgs/${org}/documents?q=notes`).set(bearer(B))
    expect(list.body.items).toHaveLength(1)
    const dl = await http.get(`/api/orgs/${org}/documents/${docId}/download`).set(bearer(B))
    expect(dl.body.url).toContain('https://signed.test/')
  })

  it('keeps organizations isolated', async () => {
    C = await register('Cleo', 'cleo@example.com')
    await verify('cleo@example.com')
    const r = await newOrg(C, 'globex')
    expect(r.status).toBe(201)
    expect((await http.get(`/api/orgs/${org}/documents`).set(bearer(C))).status).toBe(404)
    expect((await http.get(`/api/orgs/${r.body.id}/documents`).set(bearer(A))).status).toBe(404)
  })

  it('rejects expired invitations', async () => {
    await http.post(`/api/orgs/${org}/invites`).set(bearer(A)).send({ email: 'dan@example.com', role: 'member' })
    const token = tokenFrom('dan@example.com', 'invite')
    await Invite.updateMany({ email: 'dan@example.com' }, { expiresAt: new Date(Date.now() - 1000) })
    expect((await http.get(`/api/invites/${token}`)).status).toBe(410)
  })

  it('resets a password and rejects the old one', async () => {
    expect((await http.post('/api/auth/forgot').send({ email: 'nobody@example.com' })).status).toBe(204)
    expect((await http.post('/api/auth/forgot').send({ email: 'ada@example.com' })).status).toBe(204)
    const token = tokenFrom('ada@example.com', 'reset')
    expect((await http.post('/api/auth/reset').send({ token, password: 'new-password-1' })).status).toBe(204)
    expect((await http.post('/api/auth/reset').send({ token, password: 'new-password-2' })).status).toBe(400)
    expect((await http.post('/api/auth/login').send({ identifier: 'ada@example.com', password: PASSWORD })).status).toBe(401)
    expect((await http.post('/api/auth/login').send({ identifier: 'ada', password: 'new-password-1' })).status).toBe(200)
  })

  it('invites by username without revealing the email, and lists it for the invitee', async () => {
    const inv = await http.post(`/api/orgs/${org}/invites`).set(bearer(A)).send({ username: '@cleo', role: 'member' })
    expect(inv.status).toBe(201)
    expect(inv.body.to).toBe('@cleo')
    expect(JSON.stringify(inv.body)).not.toContain('cleo@example.com')
    const mine = await http.get('/api/invites/mine').set(bearer(C))
    expect(mine.body.items).toHaveLength(1)
    expect((await http.post(`/api/invites/mine/${mine.body.items[0].id}/accept`).set(bearer(C))).status).toBe(200)
  })

  it('lets people join through a single-use link', async () => {
    const link = await http.post(`/api/orgs/${org}/links`).set(bearer(A)).send({ days: 7, maxUses: 1 })
    expect(link.status).toBe(201)
    const token = link.body.url.split('/join/')[1]
    const E = await register('Eve', 'eve@example.com')
    expect((await http.post(`/api/join/${token}`).set(bearer(E))).status).toBe(200)
    const F = await register('Finn', 'finn@example.com')
    expect((await http.post(`/api/join/${token}`).set(bearer(F))).status).toBe(404)
  })

  it('shows admin routes only to the admin, and enforces quotas and suspensions', async () => {
    expect((await http.get('/api/admin/stats').set(bearer(A))).status).toBe(404)
    const ADM = await register('Admin', 'admin@example.com')
    expect((await http.get('/api/admin/stats').set(bearer(ADM))).status).toBe(404)
    await verify('admin@example.com')
    expect((await http.get('/api/admin/stats').set(bearer(ADM))).status).toBe(200)
    await http.patch(`/api/admin/orgs/${org}`).set(bearer(ADM)).send({ quotaMB: 1 })
    const big = await http.post(`/api/orgs/${org}/documents`).set(bearer(B)).field('folderId', folder).attach('files', Buffer.alloc(2 * 1024 * 1024), 'big.pdf')
    expect(big.status).toBe(413)
    const users = await http.get('/api/admin/users?q=ben').set(bearer(ADM))
    await http.patch(`/api/admin/users/${users.body.items[0].id}`).set(bearer(ADM)).send({ suspended: true })
    expect((await http.get('/api/auth/me').set(bearer(B))).status).toBe(403)
  })
})
