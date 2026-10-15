import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { env } from './config'

// Every supported provider speaks the S3 API, so one client covers them all.
// Only the endpoint and region differ. Switching provider is an env change, not a code change.
const region = env.STORAGE_PROVIDER === 'r2' ? 'auto' : (env.STORAGE_REGION ?? 'us-east-1')
const endpoint = env.STORAGE_ENDPOINT ?? (env.STORAGE_PROVIDER === 'b2' ? `https://s3.${env.STORAGE_REGION}.backblazeb2.com` : undefined)

const s3 = new S3Client({
  region,
  endpoint,
  credentials: { accessKeyId: env.STORAGE_ACCESS_KEY_ID, secretAccessKey: env.STORAGE_SECRET_ACCESS_KEY },
  // Newer SDK versions add checksum headers that Backblaze and some other providers reject.
  requestChecksumCalculation: 'WHEN_REQUIRED',
  responseChecksumValidation: 'WHEN_REQUIRED',
})

export const storageInfo = { provider: env.STORAGE_PROVIDER, bucket: env.STORAGE_BUCKET, endpoint: endpoint ?? 'AWS default' }

export const put = (Key: string, Body: Buffer, ContentType?: string) =>
  s3.send(new PutObjectCommand({ Bucket: env.STORAGE_BUCKET, Key, Body, ContentType }))
export const del = (Key: string) => s3.send(new DeleteObjectCommand({ Bucket: env.STORAGE_BUCKET, Key }))
export const signedGet = (Key: string, filename?: string, inline = false) =>
  getSignedUrl(s3, new GetObjectCommand({
    Bucket: env.STORAGE_BUCKET, Key,
    ResponseContentDisposition: filename ? `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(filename)}` : undefined,
  }), { expiresIn: 300 })
