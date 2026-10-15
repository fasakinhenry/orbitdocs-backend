import type { Types } from 'mongoose'
import { Doc, Org, Settings } from './models'

export const MB = 1024 * 1024
export interface PlatformSettings { defaultQuotaMB: number; maxFileMB: number; registrationOpen: boolean }

export async function getSettings() {
  const s = await Settings.findOneAndUpdate({ key: 'platform' }, { $setOnInsert: { key: 'platform' } }, { upsert: true, new: true, setDefaultsOnInsert: true }).lean<PlatformSettings>()
  return s!
}

// Trashed files still occupy storage, so they count until they are deleted forever.
export async function usedBytes(org: Types.ObjectId) {
  const r = await Doc.aggregate<{ b: number }>([{ $match: { org } }, { $group: { _id: null, b: { $sum: '$size' } } }])
  return r[0]?.b ?? 0
}

export async function orgQuota(org: Types.ObjectId) {
  const [o, s] = await Promise.all([Org.findById(org).select('quotaBytes').lean(), getSettings()])
  return o?.quotaBytes ?? s.defaultQuotaMB * MB
}
