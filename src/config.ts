import 'dotenv/config'
import { z } from 'zod'

const clean = <T extends z.ZodTypeAny>(t: T) => z.preprocess((v) => typeof v === 'string' ? v.trim() : v, t)
const blank = <T extends z.ZodTypeAny>(t: T) => clean(z.preprocess((v) => (v === '' ? undefined : v), t))

const schema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(5000),
  MONGODB_URI: z.string().min(1),
  CLIENT_URL: z.string().url(),
  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  STORAGE_PROVIDER: z.enum(['b2', 's3', 'r2', 'custom']).default('b2'),
  STORAGE_ENDPOINT: blank(z.string().url().optional()),
  STORAGE_REGION: blank(z.string().optional()),
  STORAGE_ACCESS_KEY_ID: clean(z.string().min(1)),
  STORAGE_SECRET_ACCESS_KEY: clean(z.string().min(1)),
  STORAGE_BUCKET: clean(z.string().min(1)),
  ADMIN_EMAIL: z.string().email(),
  RESEND_API_KEY: z.string().min(1),
  MAIL_FROM: z.string().min(3),
})

const parsed = schema.safeParse(process.env)
if (!parsed.success) {
  console.error('Missing or invalid environment variables:', Object.keys(parsed.error.flatten().fieldErrors).join(', '))
  console.error('Copy .env.example to .env and fill in every value.')
  process.exit(1)
}
const e = parsed.data
const need = [
  ...(['b2', 's3'].includes(e.STORAGE_PROVIDER) && !e.STORAGE_REGION ? ['STORAGE_REGION'] : []),
  ...(['r2', 'custom'].includes(e.STORAGE_PROVIDER) && !e.STORAGE_ENDPOINT ? ['STORAGE_ENDPOINT'] : []),
]
if (need.length) {
  console.error(`STORAGE_PROVIDER=${e.STORAGE_PROVIDER} also needs: ${need.join(', ')}`)
  process.exit(1)
}
if (e.STORAGE_PROVIDER === 'b2' && e.STORAGE_ACCESS_KEY_ID === e.STORAGE_SECRET_ACCESS_KEY) {
  console.error('Backblaze B2 requires different values for STORAGE_ACCESS_KEY_ID and STORAGE_SECRET_ACCESS_KEY.')
  process.exit(1)
}
export const env = e
