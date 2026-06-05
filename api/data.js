import { verifyUser, classify, readPrivateJson, writePrivateJson } from '../lib/auth.js';

const BLOB_NAME = 'dataset.json';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  const u = await verifyUser(req);
  if (u.status !== 200) return res.status(u.status).json({ error: u.error });
  const c = await classify(u.email);
  if (!c.approved) return res.status(403).json({ error: 'Account not approved.' });
  res.setHeader('X-User-Admin', c.admin ? '1' : '0');

  if (req.method === 'GET') {
    const data = await readPrivateJson(BLOB_NAME);
    if (!data) return res.status(200).json({ empty: true });
    return res.status(200).json(data);
  }

  if (req.method === 'POST') {
    try {
      const data = req.body;
      if (!data || !data.meta || !Array.isArray(data.accounts)) {
        return res.status(400).json({ error: 'Invalid dataset shape — not saved.' });
      }
      data.meta.published_by = u.email; // authoritative
      data.meta.published_at = new Date().toISOString();
      await writePrivateJson(BLOB_NAME, data);
      return res.status(200).json({
        ok: true, published_by: u.email,
        total_notes: data.meta.total_notes, total_accounts: data.meta.total_accounts,
      });
    } catch (e) {
      return res.status(500).json({ error: String((e && e.message) || e) });
    }
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
}
