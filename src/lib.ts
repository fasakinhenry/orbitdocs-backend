import type { NextFunction, Request, RequestHandler, Response } from 'express'
import jwt from 'jsonwebtoken'
import { Types } from 'mongoose'
export { del, put, signedGet } from './storage'
import { env } from './config'
import { Audit, Membership, Org, ROLES, User, type Role } from './models'

declare global {
  namespace Express {
    interface Request { uid?: string; role?: Role }
  }
}

export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export const h = (fn: (req: Request, res: Response) => Promise<unknown>): RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next) }

// Tokens: short-lived access token in the response body, long-lived refresh token in an httpOnly cookie.
export const signAccess = (uid: string) => jwt.sign({ sub: uid }, env.JWT_ACCESS_SECRET, { expiresIn: '15m' })
const prod = env.NODE_ENV === 'production'
const cookie = { httpOnly: true, secure: prod, sameSite: prod ? ('none' as const) : ('lax' as const), path: '/api/auth' }
export const setRefresh = (res: Response, uid: string) =>
  res.cookie('rt', jwt.sign({ sub: uid }, env.JWT_REFRESH_SECRET, { expiresIn: '30d' }), { ...cookie, maxAge: 30 * 864e5 })
export const clearRefresh = (res: Response) => res.clearCookie('rt', cookie)
export const verifyRefresh = (t: string | undefined) => {
  try { return t ? (jwt.verify(t, env.JWT_REFRESH_SECRET) as { sub: string; iat: number }) : null } catch { return null }
}

export async function auth(req: Request, _res: Response, next: NextFunction) {
  try {
    const t = req.headers.authorization?.replace(/^Bearer /, '')
    const uid = (jwt.verify(t ?? '', env.JWT_ACCESS_SECRET) as { sub: string }).sub
    const u = await User.findById(uid).select('suspended').lean()
    if (!u) throw new HttpError(401, 'Your session has expired. Sign in again.')
    if (u.suspended) throw new HttpError(403, 'This account has been suspended.')
    req.uid = uid
    next()
  } catch (e) { next(e instanceof HttpError ? e : new HttpError(401, 'Your session has expired. Sign in again.')) }
}

export const orgOf = (req: Request) => new Types.ObjectId(req.params.orgId)

// Organization boundary: a user with no membership gets 404, so other orgs are never revealed.
export const member = (min: Role): RequestHandler => async (req, _res, next) => {
  try {
    if (!Types.ObjectId.isValid(req.params.orgId)) throw new HttpError(404, 'Organization not found.')
    const m = await Membership.findOne({ user: req.uid, org: req.params.orgId }).lean()
    if (!m) throw new HttpError(404, 'Organization not found.')
    if (await Org.exists({ _id: req.params.orgId, suspended: true })) throw new HttpError(403, 'This workspace has been suspended. Contact support.')
    if (ROLES.indexOf(m.role) < ROLES.indexOf(min)) throw new HttpError(403, 'You do not have permission to do this.')
    req.role = m.role
    next()
  } catch (e) { next(e) }
}

export const audit = (org: Types.ObjectId, actor: string, action: string, detail?: string) =>
  Audit.create({ org, actor, action, detail })
