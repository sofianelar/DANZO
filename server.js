require('dotenv').config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const dataDir = path.join(__dirname, "data");

if (!ADMIN_PASSWORD || !SESSION_SECRET) {
  console.error("Missing ADMIN_PASSWORD or SESSION_SECRET. Copy .env.example to .env and set both values.");
  process.exit(1);
}
fs.mkdirSync(dataDir, { recursive: true });

const productsFile = path.join(dataDir, "products.json");
const ordersFile = path.join(dataDir, "orders.json");

const starterProducts = [
  { id: 1, name: "تيشورت Essential", category: "تيشورتات", price: 2200, sizes: "S / M / L / XL", image: "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=700&q=80", tag: "الأكثر طلبًا", active: true },
  { id: 2, name: "سويت Urban", category: "سويتات", price: 3800, sizes: "M / L / XL", image: "https://images.unsplash.com/photo-1556821840-3a63f95609a7?auto=format&fit=crop&w=700&q=80", tag: "جديد", active: true },
  { id: 3, name: "جاكيت Classic", category: "جاكيتات", price: 6500, sizes: "M / L / XL", image: "https://images.unsplash.com/photo-1551028719-00167b16eac5?auto=format&fit=crop&w=700&q=80", tag: "ستايل", active: true },
  { id: 4, name: "قميص Casual", category: "قمصان", price: 3200, sizes: "S / M / L / XL", image: "https://images.unsplash.com/photo-1598033129183-c4f50c736f10?auto=format&fit=crop&w=700&q=80", tag: "", active: true },
  { id: 5, name: "سروال Denim", category: "سراويل", price: 4200, sizes: "38 / 40 / 42 / 44", image: "https://images.unsplash.com/photo-1542272604-787c3835535d?auto=format&fit=crop&w=700&q=80", tag: "", active: true },
  { id: 6, name: "تيشورت Street", category: "تيشورتات", price: 2500, sizes: "S / M / L / XL", image: "https://images.unsplash.com/photo-1503342217505-b0a15ec3261c?auto=format&fit=crop&w=700&q=80", tag: "جديد", active: true },
  { id: 7, name: "سويت Minimal", category: "سويتات", price: 4000, sizes: "M / L / XL", image: "https://images.unsplash.com/photo-1578681994506-b8f463449011?auto=format&fit=crop&w=700&q=80", tag: "", active: true },
  { id: 8, name: "جاكيت Modern", category: "جاكيتات", price: 7200, sizes: "M / L / XL", image: "https://images.unsplash.com/photo-1548126032-079a0fb0099d?auto=format&fit=crop&w=700&q=80", tag: "", active: true }
];
if (!fs.existsSync(productsFile)) fs.writeFileSync(productsFile, JSON.stringify(starterProducts, null, 2));
if (!fs.existsSync(ordersFile)) fs.writeFileSync(ordersFile, "[]");

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { return []; }
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function adminOnly(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).json({ error: "خاصك تدخل كمسؤول أولاً." });
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(session({
  name: "danzo.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 4 }
}));

app.get("/api/products", (req, res) => {
  res.json(readJson(productsFile).filter(p => p.active !== false));
});

app.post("/api/orders", (req, res) => {
  const { name, phone, wilaya, address, notes, items } = req.body || {};
  if (!name || !phone || !wilaya || !address || !Array.isArray(items) || !items.length) {
    return res.status(400).json({ error: "كمّل معلومات الطلب والمنتجات." });
  }
  if (String(name).length > 100 || String(phone).length > 30 || String(address).length > 300) {
    return res.status(400).json({ error: "بعض المعلومات طويلة بزاف." });
  }
  const products = readJson(productsFile);
  const orderItems = [];
  for (const item of items) {
    const product = products.find(p => p.id === Number(item.id) && p.active !== false);
    const qty = Math.max(0, Math.min(20, Math.floor(Number(item.qty) || 0)));
    if (!product || qty < 1) continue;
    orderItems.push({ id: product.id, name: product.name, price: product.price, qty, size: String(item.size || "") });
  }
  if (!orderItems.length) return res.status(400).json({ error: "السلة ما فيها حتى منتج صالح." });
  const total = orderItems.reduce((sum, item) => sum + item.price * item.qty, 0);
  const orders = readJson(ordersFile);
  const order = {
    id: "DM-" + Date.now().toString().slice(-8),
    createdAt: new Date().toISOString(),
    name: String(name).trim(), phone: String(phone).trim(),
    wilaya: String(wilaya).trim(), address: String(address).trim(),
    notes: String(notes || "").slice(0, 500),
    items: orderItems, total, status: "جديد"
  };
  orders.unshift(order);
  writeJson(ordersFile, orders);
  res.status(201).json({ ok: true, orderId: order.id });
});

app.post("/api/admin/login", (req, res) => {
  const password = String((req.body || {}).password || "");
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "كلمة السر غير صحيحة." });
  req.session.isAdmin = true;
  res.json({ ok: true });
});
app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get("/api/admin/me", (req, res) => res.json({ isAdmin: !!(req.session && req.session.isAdmin) }));

app.get("/api/admin/all-products", adminOnly, (req, res) => res.json(readJson(productsFile)));
app.get("/api/admin/orders", adminOnly, (req, res) => res.json(readJson(ordersFile)));
app.patch("/api/admin/orders/:id", adminOnly, (req, res) => {
  const allowed = ["جديد", "تم التأكيد", "تم الشحن", "مكتمل", "ملغى"];
  const orders = readJson(ordersFile);
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: "الطلب غير موجود." });
  if (!allowed.includes(req.body.status)) return res.status(400).json({ error: "حالة غير صالحة." });
  order.status = req.body.status;
  writeJson(ordersFile, orders);
  res.json({ ok: true });
});

app.post("/api/admin/products", adminOnly, (req, res) => {
  const { name, category, price, sizes, image, tag } = req.body || {};
  if (!name || !category || !Number.isFinite(Number(price)) || Number(price) < 0) {
    return res.status(400).json({ error: "الاسم والصنف والسعر مطلوبين." });
  }
  const products = readJson(productsFile);
  const product = {
    id: Math.max(0, ...products.map(p => Number(p.id) || 0)) + 1,
    name: String(name).trim().slice(0, 100),
    category: String(category).trim().slice(0, 60),
    price: Math.round(Number(price)),
    sizes: String(sizes || "S / M / L / XL").slice(0, 100),
    image: String(image || "").trim().slice(0, 1000),
    tag: String(tag || "").trim().slice(0, 30),
    active: true
  };
  products.unshift(product);
  writeJson(productsFile, products);
  res.status(201).json(product);
});
app.patch("/api/admin/products/:id", adminOnly, (req, res) => {
  const products = readJson(productsFile);
  const p = products.find(x => x.id === Number(req.params.id));
  if (!p) return res.status(404).json({ error: "المنتج غير موجود." });
  const b = req.body || {};
  if (b.name !== undefined) p.name = String(b.name).trim().slice(0, 100);
  if (b.category !== undefined) p.category = String(b.category).trim().slice(0, 60);
  if (b.price !== undefined && Number.isFinite(Number(b.price)) && Number(b.price) >= 0) p.price = Math.round(Number(b.price));
  if (b.sizes !== undefined) p.sizes = String(b.sizes).slice(0, 100);
  if (b.image !== undefined) p.image = String(b.image).trim().slice(0, 1000);
  if (b.tag !== undefined) p.tag = String(b.tag).trim().slice(0, 30);
  if (b.active !== undefined) p.active = !!b.active;
  writeJson(productsFile, products);
  res.json(p);
});
app.delete("/api/admin/products/:id", adminOnly, (req, res) => {
  const products = readJson(productsFile);
  const p = products.find(x => x.id === Number(req.params.id));
  if (!p) return res.status(404).json({ error: "المنتج غير موجود." });
  p.active = false;
  writeJson(productsFile, products);
  res.json({ ok: true });
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));

app.listen(PORT, () => console.log(`DANZO MEN running at http://localhost:${PORT}`));
