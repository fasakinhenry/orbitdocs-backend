Object.assign(process.env, {
  NODE_ENV: 'test',
  MONGODB_URI: 'mongodb://localhost:27017/orbitdocs-test',
  CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(32),
  JWT_REFRESH_SECRET: 'b'.repeat(32),
  STORAGE_PROVIDER: 'b2', STORAGE_REGION: 'us-west-004', STORAGE_ACCESS_KEY_ID: 'test', STORAGE_SECRET_ACCESS_KEY: 'test', STORAGE_BUCKET: 'test',
  ADMIN_EMAIL: 'admin@example.com',
  RESEND_API_KEY: 'test', MAIL_FROM: 'OrbitDocs <test@example.com>',
})
