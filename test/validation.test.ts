import { describe, expect, it } from 'vitest'
import request from 'supertest'
import { app } from '../src/app'

const http = request(app)

describe('validation and auth guards (no database)', () => {
  it('answers the health check', async () => {
    const r = await http.get('/health')
    expect(r.status).toBe(200)
  })

  it('rejects an invalid email and a short password with field errors', async () => {
    const r = await http.post('/api/auth/register').send({ name: 'Ada', email: 'nope', password: 'short' })
    expect(r.status).toBe(400)
    expect(r.body.error.fields).toHaveProperty('email')
    expect(r.body.error.fields).toHaveProperty('password')
  })

  it('requires a session for private routes', async () => {
    expect((await http.get('/api/auth/me')).status).toBe(401)
    expect((await http.get('/api/orgs/64b7f0f0f0f0f0f0f0f0f0f0/documents')).status).toBe(401)
    expect((await http.post('/api/orgs').send({})).status).toBe(401)
  })

  it('rejects malformed invitation tokens before touching the database', async () => {
    expect((await http.get('/api/invites/short')).status).toBe(400)
  })

  it('hides admin routes behind a plain 404', async () => {
    expect((await http.get('/api/admin/stats')).status).toBe(404)
    expect((await http.get('/api/admin/users').set('Authorization', 'Bearer not-a-token')).status).toBe(404)
  })

  it('returns JSON for unknown routes', async () => {
    const r = await http.get('/api/nothing-here')
    expect(r.status).toBe(404)
    expect(r.body.error.message).toBeTruthy()
  })
})
