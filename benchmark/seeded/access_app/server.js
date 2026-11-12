const express = require('express');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const { requireAuth, requireRole } = require('./auth');

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

app.post('/api/change-password', requireAuth, async (req, res) => { // expect: AUTH015
  const passwordHash = await bcrypt.hash(req.body.password, 12);
  await prisma.user.update({ where: { id: req.user.id }, data: { passwordHash } });
  res.json({ ok: true });
});

app.post('/api/admin/flags', requireAuth, async (req, res) => { // expect: AUTH017
  await prisma.flag.update({ where: { name: req.body.name }, data: { enabled: req.body.enabled === true } });
  res.json({ ok: true });
});

app.post('/api/admin/maintenance', requireAuth, requireRole('admin'), async (req, res) => {
  await prisma.flag.update({ where: { name: 'maintenance' }, data: { enabled: req.body.on === true } });
  res.json({ ok: true });
});

app.get('/api/projects', requireAuth, async (req, res) => { // expect: AUTH016
  res.json(await prisma.project.findMany());
});

app.get('/api/projects/mine', requireAuth, async (req, res) => {
  res.json(await prisma.project.findMany({ where: { orgId: req.user.orgId } }));
});

app.listen(3000);
