require('dotenv').config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const crypto = require("crypto");
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
  if (!fs.existsSync(file)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    if (Array.isArray(data)) return data;
    throw new Error("not an array");
  } catch (err) {
    // لا نضيّع البيانات: نحفظ نسخة من الملف التالف قبل أي كتابة جديدة
    const backup = file + ".corrupt-" + Date.now();
    try { fs.copyFileSync(file, backup); } catch {}
    console.error("Corrupt data file " + file + " - backup saved to " + backup);
    return [];
  }
}
function writeJson(file, data) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);   // كتابة ذرية: الملف ما يتخربش إذا توقف السيرفر في النص
}
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function makeLimiter(max, windowMs) {
  const hits = new Map();
  const fresh = ip => { const h = hits.get(ip); if (h && Date.now() - h.first > windowMs) { hits.delete(ip); return null; } return h || null; };
  return {
    blocked: ip => { const h = fresh(ip); return !!h && h.count >= max; },
    hit: ip => { const h = fresh(ip); if (h) h.count++; else hits.set(ip, { count: 1, first: Date.now() }); },
    reset: ip => hits.delete(ip)
  };
}
const loginLimiter = makeLimiter(8, 15 * 60 * 1000);    // 8 محاولات فاشلة / 15 دقيقة
const orderLimiter = makeLimiter(30, 60 * 60 * 1000);   // 30 طلب / ساعة لكل IP
function adminOnly(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).json({ error: "خاصك تدخل كمسؤول أولاً." });
}

if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);  // خلف HTTPS proxy (Render, Railway...)
app.use(helmet({ contentSecurityPolicy: false }));
app.use("/api", (req, res, next) => { res.set("Cache-Control", "no-store"); next(); });  // المتصفح ما يحفظش نسخة قديمة من المنتجات
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
  if (orderLimiter.blocked(req.ip)) return res.status(429).json({ error: "طلبات كثيرة، عاود بعد شوية." });
  orderLimiter.hit(req.ip);
  const { name, phone, wilaya, address, notes, items, orderId } = req.body || {};
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
  const clientId = String(orderId || "").trim();
  const id = /^[A-Za-z0-9-]{6,30}$/.test(clientId) && !orders.some(o => o.id === clientId)
    ? clientId : "DM-" + Date.now().toString().slice(-8);
  const order = {
    id,
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
  if (loginLimiter.blocked(req.ip)) return res.status(429).json({ error: "محاولات كثيرة، عاود بعد 15 دقيقة." });
  const password = String((req.body || {}).password || "");
  if (!safeEqual(password, ADMIN_PASSWORD)) {
    loginLimiter.hit(req.ip);
    return res.status(401).json({ error: "كلمة السر غير صحيحة." });
  }
  loginLimiter.reset(req.ip);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "حدث خطأ." });
    req.session.isAdmin = true;
    res.json({ ok: true });
  });
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
  const idx = products.findIndex(x => x.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: "المنتج غير موجود." });
  products.splice(idx, 1);   // حذف نهائي (الطلبات القديمة تحتفظ باسم وسعر المنتج)
  writeJson(productsFile, products);
  res.json({ ok: true });
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));

const server = app.listen(PORT, () => {
  console.log(`NINJA DARK running at http://localhost:${PORT}`);
  console.log(`Data folder: ${dataDir} | products: ${readJson(productsFile).length} | orders: ${readJson(ordersFile).length}`);
});
server.on("error", err => {
  if (err.code === "EADDRINUSE") console.error(`Port ${PORT} is already used by another running copy of the server. Close it (Ctrl+C in its terminal, or run: npx kill-port ${PORT}) then start again.`);
  else console.error(err);
  process.exit(1);
});
