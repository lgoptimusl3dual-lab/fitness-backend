import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import crypto from 'crypto'
import { createClient } from '@supabase/supabase-js'

const app = express()
app.use(cors())
app.use(express.json())

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE
)

// --- Telegram initData verify ---
function verifyTelegramInitData(initData, botToken) {
  const params = new URLSearchParams(initData)
  const hash = params.get('hash')
  if (!hash) return { ok: false, reason: 'no hash' }
  params.delete('hash')

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')

  const secretKey = crypto.createHash('sha256').update(botToken).digest()
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex')

  const ok = hmac === hash
  return { ok, reason: ok ? null : 'bad signature' }
}

function getTelegramUserFromInitData(initData) {
  const params = new URLSearchParams(initData)
  const userStr = params.get('user')
  if (!userStr) return null
  return JSON.parse(userStr)
}

// --- Auth: verify initData and upsert user ---
app.post('/api/auth/telegram', async (req, res) => {
  const { initData } = req.body
  if (!initData) return res.status(400).json({ error: 'initData required' })

  const ver = verifyTelegramInitData(initData, process.env.BOT_TOKEN)
  if (!ver.ok) return res.status(401).json({ error: 'Invalid initData', reason: ver.reason })

  const tgUser = getTelegramUserFromInitData(initData)
  if (!tgUser?.id) return res.status(400).json({ error: 'No user in initData' })

  // upsert in app_users
  const { error } = await supabase.from('app_users').upsert({
    telegram_id: tgUser.id,
    username: tgUser.username ?? null,
    first_name: tgUser.first_name ?? null
  })

  if (error) return res.status(500).json({ error: error.message })

  // супер-просто: возвращаем telegram_id как идентификатор
  // позже можно сделать JWT/сессию
  res.json({ telegramId: tgUser.id })
})

// Middleware: require initData for every request (просто и безопасно)
async function requireUser(req, res, next) {
  const initData = req.headers['x-telegram-initdata']
  if (!initData) return res.status(401).json({ error: 'x-telegram-initdata header required' })

  const ver = verifyTelegramInitData(initData, process.env.BOT_TOKEN)
  if (!ver.ok) return res.status(401).json({ error: 'Invalid initData' })

  const tgUser = getTelegramUserFromInitData(initData)
  if (!tgUser?.id) return res.status(401).json({ error: 'No user' })

  req.telegramId = tgUser.id
  next()
}

// --- Get workout by date (or null) ---
app.get('/api/workouts', requireUser, async (req, res) => {
  const date = req.query.date
  if (!date) return res.status(400).json({ error: 'date=YYYY-MM-DD required' })

  const { data: w, error: wErr } = await supabase
    .from('workouts')
    .select('id,user_id,workout_date,title,notes')
    .eq('user_id', req.telegramId)
    .eq('workout_date', date)
    .maybeSingle()

  if (wErr) return res.status(500).json({ error: wErr.message })
  if (!w) return res.json(null)

  const { data: ex, error: exErr } = await supabase
    .from('workout_exercises')
    .select('id,name,position')
    .eq('workout_id', w.id)
    .order('position')

  if (exErr) return res.status(500).json({ error: exErr.message })

  // sets for all exercises
  const exIds = ex.map(e => e.id)
  const { data: sets, error: sErr } = await supabase
    .from('workout_sets')
    .select('id,exercise_id,set_no,reps,weight_kg')
    .in('exercise_id', exIds.length ? exIds : ['00000000-0000-0000-0000-000000000000'])
    .order('set_no')

  if (sErr) return res.status(500).json({ error: sErr.message })

  const byExercise = new Map()
  for (const s of sets) {
    const arr = byExercise.get(s.exercise_id) ?? []
    arr.push(s)
    byExercise.set(s.exercise_id, arr)
  }

  res.json({
    ...w,
    exercises: ex.map(e => ({
      ...e,
      sets: byExercise.get(e.id) ?? []
    }))
  })
})

// --- Upsert workout (with exercises + sets) ---
app.post('/api/workouts', requireUser, async (req, res) => {
  const { workout_date, title, notes, exercises } = req.body
  if (!workout_date) return res.status(400).json({ error: 'workout_date required' })
  if (!Array.isArray(exercises)) return res.status(400).json({ error: 'exercises[] required' })

  // 1) upsert workout (1 per day)
  const { data: w, error: wErr } = await supabase
    .from('workouts')
    .upsert({
      user_id: req.telegramId,
      workout_date,
      title: title ?? null,
      notes: notes ?? null
    }, { onConflict: 'user_id,workout_date' })
    .select('id,user_id,workout_date,title,notes')
    .single()

  if (wErr) return res.status(500).json({ error: wErr.message })

  // 2) delete old exercises+sets then insert fresh (простая стратегия для MVP)
  const { data: oldEx } = await supabase
    .from('workout_exercises')
    .select('id')
    .eq('workout_id', w.id)

  const oldIds = (oldEx ?? []).map(x => x.id)
  if (oldIds.length) {
    await supabase.from('workout_sets').delete().in('exercise_id', oldIds)
  }
  await supabase.from('workout_exercises').delete().eq('workout_id', w.id)

  // 3) insert exercises
  const exRows = exercises.map((e, idx) => ({
    workout_id: w.id,
    name: e.name,
    position: idx + 1
  }))

  const { data: insertedEx, error: insExErr } = await supabase
    .from('workout_exercises')
    .insert(exRows)
    .select('id,name,position')

  if (insExErr) return res.status(500).json({ error: insExErr.message })

  // 4) insert sets
  const setRows = []
  for (let i = 0; i < exercises.length; i++) {
    const ex = exercises[i]
    const exId = insertedEx[i].id
    const sets = Array.isArray(ex.sets) ? ex.sets : []
    sets.forEach((s, idx) => {
      setRows.push({
        exercise_id: exId,
        set_no: idx + 1,
        reps: Number(s.reps ?? 0),
        weight_kg: Number(s.weight_kg ?? 0)
      })
    })
  }

  if (setRows.length) {
    const { error: insSErr } = await supabase.from('workout_sets').insert(setRows)
    if (insSErr) return res.status(500).json({ error: insSErr.message })
  }

  res.json({ ok: true, workout_id: w.id })
})

app.listen(process.env.PORT, () => {
  console.log(`Backend running on http://localhost:${process.env.PORT}`)
})