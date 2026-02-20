import "dotenv/config";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(express.json());

// --- Supabase ---
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE in env");
}

const supabase = createClient(SUPABASE_URL ?? "", SUPABASE_SERVICE_ROLE ?? "");

// --- Telegram WebApp initData verify (CORRECT) ---
function verifyTelegramInitData(initData, botToken) {
  if (!initData) return { ok: false, reason: "no initData" };
  if (!botToken) return { ok: false, reason: "no BOT_TOKEN in env" };

  const token = String(botToken).trim();

  // Telegram initData is querystring. Иногда уже декодирован, иногда нет — обработаем безопасно.
  let raw = String(initData);
  try {
    raw = decodeURIComponent(raw);
  } catch {
    // если уже декодировано — ок
  }

  const params = new URLSearchParams(raw);
  const hash = params.get("hash");
  if (!hash) return { ok: false, reason: "no hash" };
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  // ✅ Правильный secretKey для Mini Apps:
  // secretKey = HMAC_SHA256(key="WebAppData", message=botToken)
  const secretKey = crypto.createHmac("sha256", "WebAppData").update(token).digest();

  // computed = HMAC_SHA256(key=secretKey, message=dataCheckString) as hex
  const computed = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

  const ok =
    computed.length === hash.length &&
    crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(hash));

  return {
    ok,
    reason: ok ? null : "hash_mismatch",
    debug: {
      incomingPreview: hash.slice(0, 10),
      computedHexPreview: computed.slice(0, 10),
    },
  };
}

function getTelegramUserFromInitData(initData) {
  let raw = String(initData || "");
  try {
    raw = decodeURIComponent(raw);
  } catch {}

  const params = new URLSearchParams(raw);
  const userStr = params.get("user");
  if (!userStr) return null;

  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
}

// --- Health ---
app.get("/health", (req, res) => res.json({ ok: true }));

// --- Auth: verify initData and upsert user ---
app.post("/api/auth/telegram", async (req, res) => {
  const { initData } = req.body;
  if (!initData) return res.status(400).json({ error: "initData required" });

  const ver = verifyTelegramInitData(initData, process.env.BOT_TOKEN);
  if (!ver.ok) return res.status(401).json({ error: "Invalid initData", reason: ver.reason, debug: ver.debug });

  const tgUser = getTelegramUserFromInitData(initData);
  if (!tgUser?.id) return res.status(400).json({ error: "No user in initData" });

  // upsert in app_users
  const { error } = await supabase.from("app_users").upsert({
    telegram_id: tgUser.id,
    username: tgUser.username ?? null,
    first_name: tgUser.first_name ?? null,
  });

  if (error) return res.status(500).json({ error: error.message });

  res.json({ telegramId: tgUser.id });
});

// Middleware: require initData for every request
async function requireUser(req, res, next) {
  const initData = req.headers["x-telegram-initdata"];
  if (!initData) return res.status(401).json({ error: "x-telegram-initdata header required" });

  const ver = verifyTelegramInitData(initData, process.env.BOT_TOKEN);
  if (!ver.ok) return res.status(401).json({ error: "Invalid initData", reason: ver.reason });

  const tgUser = getTelegramUserFromInitData(initData);
  if (!tgUser?.id) return res.status(401).json({ error: "No user" });

  req.telegramId = tgUser.id;
  next();
}

// --- Get workout by date (or null) ---
app.get("/api/workouts", requireUser, async (req, res) => {
  const date = req.query.date;
  if (!date) return res.status(400).json({ error: "date=YYYY-MM-DD required" });

  const { data: w, error: wErr } = await supabase
    .from("workouts")
    .select("id,user_id,workout_date,title,notes")
    .eq("user_id", req.telegramId)
    .eq("workout_date", date)
    .maybeSingle();

  if (wErr) return res.status(500).json({ error: wErr.message });
  if (!w) return res.json(null);

  const { data: ex, error: exErr } = await supabase
    .from("workout_exercises")
    .select("id,name,position")
    .eq("workout_id", w.id)
    .order("position");

  if (exErr) return res.status(500).json({ error: exErr.message });

  const exIds = (ex ?? []).map((e) => e.id);
  const { data: sets, error: sErr } = await supabase
    .from("workout_sets")
    .select("id,exercise_id,set_no,reps,weight_kg")
    .in("exercise_id", exIds.length ? exIds : ["00000000-0000-0000-0000-000000000000"])
    .order("set_no");

  if (sErr) return res.status(500).json({ error: sErr.message });

  const byExercise = new Map();
  for (const s of sets ?? []) {
    const arr = byExercise.get(s.exercise_id) ?? [];
    arr.push(s);
    byExercise.set(s.exercise_id, arr);
  }

  res.json({
    ...w,
    exercises: (ex ?? []).map((e) => ({
      ...e,
      sets: byExercise.get(e.id) ?? [],
    })),
  });
});

// --- Upsert workout (with exercises + sets) ---
app.post("/api/workouts", requireUser, async (req, res) => {
  const { workout_date, title, notes, exercises } = req.body;
  if (!workout_date) return res.status(400).json({ error: "workout_date required" });
  if (!Array.isArray(exercises)) return res.status(400).json({ error: "exercises[] required" });

  const { data: w, error: wErr } = await supabase
    .from("workouts")
    .upsert(
      {
        user_id: req.telegramId,
        workout_date,
        title: title ?? null,
        notes: notes ?? null,
      },
      { onConflict: "user_id,workout_date" }
    )
    .select("id,user_id,workout_date,title,notes")
    .single();

  if (wErr) return res.status(500).json({ error: wErr.message });

  const { data: oldEx } = await supabase.from("workout_exercises").select("id").eq("workout_id", w.id);
  const oldIds = (oldEx ?? []).map((x) => x.id);

  if (oldIds.length) {
    await supabase.from("workout_sets").delete().in("exercise_id", oldIds);
  }
  await supabase.from("workout_exercises").delete().eq("workout_id", w.id);

  const exRows = exercises.map((e, idx) => ({
    workout_id: w.id,
    name: e.name,
    position: idx + 1,
  }));

  const { data: insertedEx, error: insExErr } = await supabase
    .from("workout_exercises")
    .insert(exRows)
    .select("id,name,position");

  if (insExErr) return res.status(500).json({ error: insExErr.message });

  const setRows = [];
  for (let i = 0; i < exercises.length; i++) {
    const ex = exercises[i];
    const exId = insertedEx[i].id;
    const setsArr = Array.isArray(ex.sets) ? ex.sets : [];
    setsArr.forEach((s, idx) => {
      setRows.push({
        exercise_id: exId,
        set_no: idx + 1,
        reps: Number(s.reps ?? 0),
        weight_kg: Number(s.weight_kg ?? 0),
      });
    });
  }

  if (setRows.length) {
    const { error: insSErr } = await supabase.from("workout_sets").insert(setRows);
    if (insSErr) return res.status(500).json({ error: insSErr.message });
  }

  res.json({ ok: true, workout_id: w.id });
});

// Render даёт PORT автоматически
const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});