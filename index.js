import "dotenv/config";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();

// IMPORTANT: allow custom header x-telegram-initdata (for browser preflight)
app.use(
  cors({
    origin: true,
    credentials: true,
    allowedHeaders: ["Content-Type", "x-telegram-initdata"],
    methods: ["GET", "POST", "OPTIONS"],
  })
);
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE
);

// --- Robust Telegram initData verify ---
function safeEq(a, b) {
  try {
    const ab = Buffer.from(a);
    const bb = Buffer.from(b);
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

function toBase64Url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function verifyTelegramInitData(initData, botToken, maxAgeSec = 24 * 60 * 60) {
  if (!initData || typeof initData !== "string") {
    return { ok: false, reason: "empty_initData" };
  }
  if (!botToken || typeof botToken !== "string") {
    return { ok: false, reason: "empty_botToken" };
  }

  const token = botToken.trim();

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return { ok: false, reason: "no_hash" };
  params.delete("hash");

  // auth_date check (optional but good)
  const authDateStr = params.get("auth_date");
  if (authDateStr) {
    const authDate = Number(authDateStr);
    const now = Math.floor(Date.now() / 1000);
    if (Number.isFinite(authDate) && now - authDate > maxAgeSec) {
      return { ok: false, reason: "auth_date_expired" };
    }
  }

  // data_check_string: sorted key=value joined by \n
  const pairs = [];
  for (const [k, v] of params.entries()) pairs.push([k, v]);
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join("\n");

  // secret_key = sha256(bot_token)
  const secretKey = crypto.createHash("sha256").update(token).digest();

  // computed hashes
  const hmacBuf = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest();
  const computedHex = hmacBuf.toString("hex");           // common
  const computedB64Url = toBase64Url(hmacBuf);           // just in case

  const incoming = hash.trim();
  const incomingLower = incoming.toLowerCase();

  const ok =
    safeEq(computedHex, incomingLower) ||
    safeEq(computedB64Url, incoming) ||
    safeEq(computedB64Url, incomingLower);

  if (!ok) {
    return {
      ok: false,
      reason: "hash_mismatch",
      debug: {
        incomingPreview: incoming.slice(0, 10),
        computedHexPreview: computedHex.slice(0, 10),
        computedB64Preview: computedB64Url.slice(0, 10),
      },
    };
  }

  return { ok: true };
}

function getTelegramUserFromInitData(initData) {
  const params = new URLSearchParams(initData);
  const userStr = params.get("user");
  if (!userStr) return null;
  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
}

// --- Auth: verify initData and upsert user ---
app.post("/api/auth/telegram", async (req, res) => {
  const { initData } = req.body;
  if (!initData) return res.status(400).json({ error: "initData required" });

  const ver = verifyTelegramInitData(initData, process.env.BOT_TOKEN);
  if (!ver.ok) {
    // вернём reason (без секретов)
    return res.status(401).json({ error: "Invalid initData", reason: ver.reason, debug: ver.debug ?? null });
  }

  const tgUser = getTelegramUserFromInitData(initData);
  if (!tgUser?.id) return res.status(400).json({ error: "No user in initData" });

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

  const ver = verifyTelegramInitData(String(initData), process.env.BOT_TOKEN);
  if (!ver.ok) return res.status(401).json({ error: "Invalid initData", reason: ver.reason });

  const tgUser = getTelegramUserFromInitData(String(initData));
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

  const exIds = ex.map((e) => e.id);
  const { data: sets, error: sErr } = await supabase
    .from("workout_sets")
    .select("id,exercise_id,set_no,reps,weight_kg")
    .in("exercise_id", exIds.length ? exIds : ["00000000-0000-0000-0000-000000000000"])
    .order("set_no");

  if (sErr) return res.status(500).json({ error: sErr.message });

  const byExercise = new Map();
  for (const s of sets) {
    const arr = byExercise.get(s.exercise_id) ?? [];
    arr.push(s);
    byExercise.set(s.exercise_id, arr);
  }

  res.json({
    ...w,
    exercises: ex.map((e) => ({
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

  const { data: oldEx } = await supabase
    .from("workout_exercises")
    .select("id")
    .eq("workout_id", w.id);

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

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});