import mongoose from 'mongoose'
import { env } from './config'
import { app, log } from './app'

mongoose.connect(env.MONGODB_URI).then(() => {
  app.listen(env.PORT, () => log.info(`OrbitDocs API listening on ${env.PORT}`))
}).catch((e) => { log.fatal(e, 'Could not connect to MongoDB'); process.exit(1) })
