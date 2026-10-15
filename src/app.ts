import express, { type NextFunction, type Request, type Response } from 'express'
import cors from 'cors'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import rateLimit from 'express-rate-limit'
import multer from 'multer'
import pino from 'pino'
import pinoHttp from 'pino-http'
import { ZodError } from 'zod'
import { env } from './config'
import { HttpError } from './lib'
import routes from './routes'
import adminRouter from './admin'

export const log = pino({ level: env.NODE_ENV === 'production' ? 'info' : env.NODE_ENV === 'test' ? 'silent' : 'debug' })
export const app = express()
app.set('trust proxy', 1)
app.use(helmet())
app.use(cors({ origin: env.CLIENT_URL, credentials: true }))
app.use(pinoHttp({ logger: log }))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: true, legacyHeaders: false, skip: () => env.NODE_ENV === 'test' }))

app.get('/health', (_req, res) => { res.json({ ok: true }) })
app.use('/api/admin', adminRouter)
app.use('/api', routes)
app.use((_req, res) => { res.status(404).json({ error: { message: 'Not found.' } }) })

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ZodError) return res.status(400).json({ error: { message: 'Check the fields and try again.', fields: err.flatten().fieldErrors } })
  if (err instanceof HttpError) return res.status(err.status).json({ error: { message: err.message } })
  if (err instanceof multer.MulterError) return res.status(400).json({ error: { message: err.message } })
  if ((err as { code?: number }).code === 11000) return res.status(409).json({ error: { message: 'That value is already taken.' } })
  log.error(err)
  res.status(500).json({ error: { message: 'Something went wrong on our side.' } })
})

