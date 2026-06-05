import { put, get } from '@vercel/blob';

const ALLOW_NAME = 'allowlist.json';

// ---- Private blob helpers (data is never exposed at a public URL) ----
export async function readPrivateJson(name) {
  try {
    const res = await get(name, { access: 'private', useCache: false });
    if (!res) return null;
    const text = await new Response(res.stream).text();
    return text ? JSON.parse(text) : null;
  } catch (e) {
    return null; // missing or unreadable -> treat as empty
  }
}
export async function writePrivateJson(name, obj) {
  await put(name, JSON.stringify(obj), {
    access: 'private',
    contentType: 'application/json',
    allowOverwrite: true,
    addRandomSuffix: false,
  });
}

// ---- Verify a Supabase access token -> { status, email } | { status, error } ----
export async function verifyUser(req) {
  const url = process.env.SUPABASE_URL;
  const anon = process.env.SUPABASE_ANON_KEY;
  const auth = req.headers['authorization'] || req.headers['Authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!url || !anon) return { status: 500, error: 'Server auth not configured.' };
  if (!token) return { status: 401, error: 'Not signed in.' };
  try {
    const r = await fetch(url.replace(/\/+$/, '') + '/auth/v1/user', {
      headers: { Authorization: 'Bearer ' + token, apikey: anon },
    });
    if (!r.ok) return { status: 401, error: 'Invalid or expired session.' };
    const u = await r.json();
    const email = (u && u.email ? String(u.email) : '').toLowerCase();
    if (!email) return { status: 401, error: 'No email on account.' };
    return { status: 200, email };
  } catch (e) {
    return { status: 401, error: 'Could not verify session.' };
  }
}

function superAdmins() {
  return (process.env.ADMIN_EMAILS || '')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

export async function readAllowlist() {
  const d = await readPrivateJson(ALLOW_NAME);
  if (!d) return { members: [], admins: [] };
  return {
    members: Array.isArray(d.members) ? d.members : [],
    admins: Array.isArray(d.admins) ? d.admins : [],
  };
}

export async function writeAllowlist(obj) {
  const norm = (a) => [...new Set((a || []).map((e) => String(e).trim().toLowerCase()).filter(Boolean))];
  const clean = {
    members: norm(obj.members),
    admins: norm(obj.admins),
    updated_at: new Date().toISOString(),
    updated_by: obj.updated_by || '',
  };
  await writePrivateJson(ALLOW_NAME, clean);
  return clean;
}

// ---- Approval + admin status from env super-admins + Blob allowlist ----
export async function classify(email) {
  const sa = superAdmins();
  const al = await readAllowlist();
  const isSuper = sa.includes(email);
  const admin = isSuper || al.admins.includes(email);
  const approved = admin || al.members.includes(email);
  return { approved, admin, isSuper, list: al, superAdmins: sa };
}
