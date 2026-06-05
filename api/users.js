import { verifyUser, classify, readAllowlist, writeAllowlist } from '../lib/auth.js';

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  const u = await verifyUser(req);
  if (u.status !== 200) return res.status(u.status).json({ error: u.error });
  const c = await classify(u.email);
  if (!c.admin) return res.status(403).json({ error: 'Admins only.' });

  if (req.method === 'GET') {
    return res.status(200).json({
      members: c.list.members, admins: c.list.admins,
      superAdmins: c.superAdmins, me: u.email,
    });
  }

  if (req.method === 'POST') {
    const body = req.body || {};
    const action = String(body.action || '');
    const email = String(body.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'A valid email is required.' });

    const cur = await readAllowlist();
    const members = new Set(cur.members);
    const admins = new Set(cur.admins);
    const isSuper = c.superAdmins.includes(email);

    if (action === 'add') {
      members.add(email);
    } else if (action === 'remove') {
      if (isSuper) return res.status(400).json({ error: 'Cannot remove a super-admin (managed via ADMIN_EMAILS).' });
      members.delete(email); admins.delete(email);
    } else if (action === 'makeAdmin') {
      members.add(email); admins.add(email);
    } else if (action === 'removeAdmin') {
      if (isSuper) return res.status(400).json({ error: 'Cannot change a super-admin.' });
      admins.delete(email);
    } else {
      return res.status(400).json({ error: 'Unknown action.' });
    }

    const saved = await writeAllowlist({ members: [...members], admins: [...admins], updated_by: u.email });
    return res.status(200).json({
      members: saved.members, admins: saved.admins,
      superAdmins: c.superAdmins, me: u.email,
    });
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
}
