import { createHash, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import { projects } from "./data/projects.js";
import ContactMessage from "./models/ContactMessage.js";

dotenv.config({ path: fileURLToPath(new URL("./.env", import.meta.url)) });

const app = express();
const port = Number(process.env.PORT || 4000);
const allowedOrigins = (process.env.FRONT_ORIGIN || "http://localhost:3000")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const JWT_ISSUER = "jorwi-portfolio-api";
const JWT_AUDIENCE = "jorwi-portfolio-admin";

app.disable("x-powered-by");
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed"));
  },
  methods: ["GET", "POST", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json({ limit: "12kb" }));

function databaseIsReady() {
  return mongoose.connection.readyState === 1;
}

function requireDatabase(response) {
  if (databaseIsReady()) return true;
  response.status(503).json({
    ok: false,
    code: "MONGODB_UNAVAILABLE",
    message: "El servicio de mensajes no está disponible en este momento.",
  });
  return false;
}

app.get("/api/health", (_request, response) => {
  const ready = databaseIsReady();
  response.status(ready ? 200 : 503).json({
    ok: ready,
    service: "jorwi-portfolio-api",
    database: ready ? "connected" : "disconnected",
  });
});

app.get("/api/projects", (_request, response) => {
  response.json({ projects });
});

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_request, response) => response.status(429).json({
    ok: false,
    code: "RATE_LIMITED",
    message: "Se alcanzó el límite de mensajes. Inténtalo más tarde.",
  }),
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_request, response) => response.status(429).json({
    ok: false,
    code: "LOGIN_RATE_LIMITED",
    message: "Demasiados intentos. Inténtalo de nuevo más tarde.",
  }),
});

function isValidEmail(value) {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function createTransporter() {
  const host = process.env.SMTP_HOST?.trim();
  const user = process.env.SMTP_USER?.trim();
  const password = process.env.SMTP_PASS;
  if (!host || !user || !password) return null;

  const smtpPort = Number(process.env.SMTP_PORT || 587);
  return nodemailer.createTransport({
    host,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: { user, pass: password },
  });
}

const transporter = createTransporter();

app.post("/api/contact", contactLimiter, async (request, response) => {
  const { name, email, message, website } = request.body || {};

  // Honeypot: acknowledge automated submissions without storing or forwarding them.
  if (typeof website === "string" && website.trim()) {
    return response.status(201).json({ ok: true });
  }

  const cleanName = typeof name === "string" ? name.trim() : "";
  const cleanEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
  const cleanMessage = typeof message === "string" ? message.trim() : "";

  if (
    !cleanName || cleanName.length > 100 ||
    !isValidEmail(cleanEmail) ||
    cleanMessage.length < 10 || cleanMessage.length > 4000
  ) {
    return response.status(400).json({
      ok: false,
      code: "INVALID_INPUT",
      message: "Verifica tu nombre, correo y mensaje (entre 10 y 4000 caracteres).",
    });
  }

  if (!requireDatabase(response)) return;

  try {
    const savedMessage = await ContactMessage.create({
      name: cleanName.replace(/[\r\n]+/g, " "),
      email: cleanEmail,
      message: cleanMessage,
    });

    if (transporter) {
      const recipient = process.env.CONTACT_EMAIL?.trim() || "jgjg.0503@gmail.com";
      try {
        await transporter.sendMail({
          from: process.env.SMTP_FROM?.trim() || process.env.SMTP_USER.trim(),
          to: recipient,
          replyTo: cleanEmail,
          subject: `Nuevo contacto desde tu portafolio — ${cleanName.replace(/[\r\n]+/g, " ")}`,
          text: `Nombre: ${cleanName}\nCorreo: ${cleanEmail}\n\nMensaje:\n${cleanMessage}`,
        });
      } catch (error) {
        // The message is already persisted, so email delivery must not lose it.
        console.warn("El mensaje quedó guardado, pero falló la notificación por correo:", error.message);
      }
    }

    return response.status(201).json({ ok: true, id: savedMessage.id });
  } catch (error) {
    console.error("No se pudo guardar el mensaje de contacto:", error.message);
    return response.status(503).json({
      ok: false,
      code: "MESSAGE_STORAGE_FAILED",
      message: "No se pudo guardar el mensaje. Inténtalo de nuevo o contáctame por correo.",
    });
  }
});

function equalSecret(candidate, expected) {
  const candidateHash = createHash("sha256").update(candidate).digest();
  const expectedHash = createHash("sha256").update(expected).digest();
  return timingSafeEqual(candidateHash, expectedHash);
}

function isAdminConfigured() {
  return Boolean(
    process.env.ADMIN_ACCESS_CODE && process.env.ADMIN_ACCESS_CODE.length >= 8 &&
    process.env.ADMIN_JWT_SECRET && process.env.ADMIN_JWT_SECRET.length >= 32,
  );
}

function requireAdmin(request, response, next) {
  const authorization = request.get("authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";

  if (!token || !process.env.ADMIN_JWT_SECRET) {
    return response.status(401).json({ ok: false, code: "UNAUTHORIZED", message: "Inicia sesión para continuar." });
  }

  try {
    const payload = jwt.verify(token, process.env.ADMIN_JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    if (payload.scope !== "admin:messages") throw new Error("Invalid scope");
    return next();
  } catch {
    return response.status(401).json({ ok: false, code: "UNAUTHORIZED", message: "La sesión expiró. Inicia sesión de nuevo." });
  }
}

app.post("/api/admin/login", loginLimiter, (request, response) => {
  const code = typeof request.body?.code === "string" ? request.body.code : "";

  if (!isAdminConfigured()) {
    return response.status(503).json({
      ok: false,
      code: "ADMIN_NOT_CONFIGURED",
      message: "El acceso privado aún no está configurado en la API.",
    });
  }

  if (code.length > 256 || !equalSecret(code, process.env.ADMIN_ACCESS_CODE)) {
    return response.status(401).json({
      ok: false,
      code: "INVALID_CODE",
      message: "El código no es válido.",
    });
  }

  const token = jwt.sign(
    { scope: "admin:messages" },
    process.env.ADMIN_JWT_SECRET,
    { subject: "jorwi", issuer: JWT_ISSUER, audience: JWT_AUDIENCE, expiresIn: "2h" },
  );

  return response.json({ ok: true, token });
});

app.get("/api/admin/messages", requireAdmin, async (request, response) => {
  if (!requireDatabase(response)) return;

  try {
    const parsedLimit = Number.parseInt(request.query.limit, 10);
    const limit = Number.isInteger(parsedLimit) ? Math.min(Math.max(parsedLimit, 1), 100) : 100;
    const [messages, total, unread] = await Promise.all([
      ContactMessage.find().sort({ createdAt: -1 }).limit(limit).lean(),
      ContactMessage.countDocuments(),
      ContactMessage.countDocuments({ isRead: false }),
    ]);

    return response.json({ ok: true, messages, total, unread });
  } catch (error) {
    console.error("No se pudieron consultar los mensajes:", error.message);
    return response.status(503).json({ ok: false, message: "No se pudieron consultar los mensajes." });
  }
});

app.patch("/api/admin/messages/:id", requireAdmin, async (request, response) => {
  if (!requireDatabase(response)) return;
  if (!mongoose.isValidObjectId(request.params.id)) {
    return response.status(400).json({ ok: false, message: "El identificador no es válido." });
  }

  const { isRead } = request.body || {};
  if (typeof isRead !== "boolean") {
    return response.status(400).json({ ok: false, message: "Indica si el mensaje está leído." });
  }

  try {
    const message = await ContactMessage.findByIdAndUpdate(
      request.params.id,
      { $set: { isRead, readAt: isRead ? new Date() : null } },
      { new: true, runValidators: true },
    ).lean();

    if (!message) return response.status(404).json({ ok: false, message: "No se encontró el mensaje." });
    return response.json({ ok: true, message });
  } catch (error) {
    console.error("No se pudo actualizar el mensaje:", error.message);
    return response.status(503).json({ ok: false, message: "No se pudo actualizar el mensaje." });
  }
});

app.use((request, response) => {
  response.status(404).json({ ok: false, message: "Ruta no encontrada." });
});

app.use((error, _request, response, _next) => {
  if (response.headersSent) return;
  if (error.message === "Origin not allowed") {
    return response.status(403).json({ ok: false, message: "Origen no permitido." });
  }
  if (error.type === "entity.parse.failed") {
    return response.status(400).json({ ok: false, message: "El cuerpo de la solicitud no es JSON válido." });
  }
  if (error.type === "entity.too.large") {
    return response.status(413).json({ ok: false, message: "La solicitud supera el tamaño permitido." });
  }
  console.error("Error en la API:", error.message);
  return response.status(500).json({ ok: false, message: "Error interno del servidor." });
});

async function start() {
  const mongoUri = process.env.MONGODB_URI?.trim();
  if (mongoUri) {
    try {
      await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 8000 });
      console.log("Connected to MongoDB Atlas");
    } catch {
      console.error("Could not connect to MongoDB Atlas. Check MONGODB_URI and Atlas network access.");
      process.exitCode = 1;
      return;
    }
  } else {
    console.warn("MONGODB_URI is empty; contact storage and the admin inbox are unavailable.");
  }

  app.listen(port, () => {
    console.log(`Portfolio API listening on http://localhost:${port}`);
  });
}

start();
