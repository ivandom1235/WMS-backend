// backend/service.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
// backend/service.js (add near other imports)
const { getAuthUrl, handleAuthCallback } = require("./utils/graphAuth");
const { sendTicketCompletedEmail } = require("./utils/mailer");
const { sendTicketRegisteredEmail } = require("./utils/mailer");

const app = express();

/**
 * CORS (single, correct)
 */
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["set-cookie"],
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());
app.set("trust proxy", 1);

let pool;

async function init() {
  pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
  });

  // Ensure DB is reachable before accepting requests
  await pool.query("SELECT 1");

  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`API running on http://localhost:${PORT}`);
  });
}

init().catch((err) => {
  console.error("Failed to start server:", err.message);
  process.exit(1);
});

/**
 * NEW: background status updater
 */
setInterval(async () => {
  try {
    if (!pool) return;

    await pool.execute(
      `UPDATE tickets
       SET status = 'delayed'
       WHERE status = 'registered'
         AND due_date IS NOT NULL
         AND NOW() > due_date`
    );
  } catch (e) {
    // silent
  }
}, 60 * 1000);

/**
 * Signup
 */


/**
 * Login
 */


/**
 * Raise Ticket
 */
// backend/service.js (or wherever your /api/tickets route is)
// --- ADD username support (DB insert) ---


/**
 * Ticket Status / List
 */

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "username and password required" });
    }

    const [rows] = await pool.execute(
      "SELECT id, username, location, password_hash FROM users WHERE username = ? LIMIT 1",
      [String(username).trim()]
    );

    if (!rows || rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];
    const match = await bcrypt.compare(String(password), user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = signUserToken({
      role: "executive",
      id: user.id,
      username: user.username,
    });

    setUserCookie(req, res, token);

    return res.json({
      ok: true,
      user: { id: user.id, username: user.username, location: user.location },
    });
  } catch (err) {
    return res.status(500).json({ error: "Login failed", details: err.message });
  }
});

app.post("/api/logout", (req, res) => {
  clearUserCookie(req, res);
  return res.json({ ok: true });
});

function getIp(req) {
  return (
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    null
  );
}

async function logAdminAuth({
  adminUserId,
  usernameAttempted,
  action,
  ipAddress,
  userAgent,
}) {
  const conn = await pool.getConnection();
  try {
    await conn.query(
      `INSERT INTO admin_auth_logs (admin_user_id, username_attempted, action, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        adminUserId || null,
        usernameAttempted || null,
        action,
        ipAddress,
        userAgent,
      ]
    );
  } finally {
    conn.release();
  }
}

function signAdminToken(payload) {
  const secret = process.env.ADMIN_JWT_SECRET;
  if (!secret) throw new Error("Missing ADMIN_JWT_SECRET in env");
  return jwt.sign(payload, secret, { expiresIn: "7d" });
}

function verifyAdminToken(token) {
  const secret = process.env.ADMIN_JWT_SECRET;
  if (!secret) throw new Error("Missing ADMIN_JWT_SECRET in env");
  return jwt.verify(token, secret);
}

function setAdminCookie(res, token) {
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("admin_token", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearAdminCookie(res) {
  const isProd = process.env.NODE_ENV === "production";
  res.clearCookie("admin_token", {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
  });
}

async function requireAdmin(req, res, next) {
  try {
    const token = req.cookies?.admin_token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = verifyAdminToken(token);
    req.admin = decoded;
    return next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

// -------------------- Executive Auth Helpers --------------------
// Uses cookie: user_token (set during /api/login)

function signUserToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("Missing JWT_SECRET in env");
  return jwt.sign(payload, secret, { expiresIn: "7d" });
}

function setUserCookie(req, res, token) {
  const isProd = process.env.NODE_ENV === "production";

  res.cookie("user_token", token, {
    httpOnly: true,
    secure: isProd,                 // ✅ only secure in production (HTTPS)
    sameSite: isProd ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}


  function clearUserCookie(req, res) {
  const isProd = process.env.NODE_ENV === "production";

  res.clearCookie("user_token", {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
  });
}




function requireUser(req, res, next) {
  try {
    const token = req.cookies?.user_token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (!payload?.username) return res.status(401).json({ message: "Unauthorized" });

    req.user = payload; // { role, id, username, name? }
    return next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}



app.get("/api/me", requireUser, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, username, location, name, designation FROM users WHERE id = ? LIMIT 1",
      [req.user.id]
    );
    if (!rows.length) return res.status(401).json({ message: "Unauthorized" });
    return res.json({ ok: true, user: rows[0] });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});


// -------------------- Option A: Ticket Create (snapshot users.location into tickets) --------------------

app.post("/api/tickets",requireUser, async (req, res) => {
  try {
    const username = String(req.user.username || "").trim();

    const {
      companyName,
      customerName,
      customerContactNumber,
      customerEmailId,
      category,
      requestType,
      particulars,
      description,
      modeOfPayment,
      serviceCharges,
      cost,
      dueDate,
      dueDurationText,
    } = req.body || {};

    if (
      !companyName ||
      !customerName ||
      !customerContactNumber ||
      !customerEmailId ||
      !category ||
      !requestType ||
      !modeOfPayment ||
      !dueDate
    ) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const [urows] = await pool.query(
      "SELECT location FROM users WHERE username = ? LIMIT 1",
      [username]
    );
    const location = String(urows?.[0]?.location || "").trim();
    if (!location) {
      return res.status(400).json({ message: "User location not found." });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const dueDateObj = new Date(dueDate);
      if (Number.isNaN(dueDateObj.getTime())) {
        await conn.rollback();
        return res.status(400).json({ message: "Invalid dueDate." });
      }

      const [insertResult] = await conn.query(
        `INSERT INTO tickets (
          ticket_number,
          username,
          company_name,
          location,
          customer_name,
          customer_contact_number,
          customer_email_id,
          category,
          request_type,
          particulars,
          description,
          mode_of_payment,
          service_charges,
          cost,
          due_date,
          status,
          due_duration_text
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          "__PENDING__",
          username,
          String(companyName).trim(),
          location,
          String(customerName).trim(),
          String(customerContactNumber).trim(),
          String(customerEmailId).trim(),
          String(category).trim(),
          String(requestType).trim(),
          String(particulars || ""),
          String(description || ""),
          String(modeOfPayment).trim(),
          String(serviceCharges ?? ""),
          String(cost ?? ""),
          dueDateObj,
          "registered",
          dueDurationText || null,
        ]
      );

      const id = insertResult.insertId;
      const ticketNumber = `WMS${Number(id)}`;

      await conn.query("UPDATE tickets SET ticket_number = ? WHERE id = ?", [
        ticketNumber,
        id,
      ]);

      await conn.commit();

      try {
        await sendTicketRegisteredEmail({
          to: customerEmailId,
          customerName,
          ticketNumber,
        });
      } catch (emailErr) {
        console.error("Email send FAILED:", emailErr?.message || emailErr);
      }

      return res.json({ message: "Ticket successfully raised", ticketNumber });
    } catch (err) {
      await conn.rollback();
      if (String(err?.code) === "ER_DUP_ENTRY") {
        return res.status(409).json({ message: "Duplicate ticket number generated. Try again." });
      }
      return res.status(500).json({ message: "Database error.", details: err.code || err.message });
    } finally {
      conn.release();
    }
  } catch (err) {
    return res.status(500).json({ message: "Server error.", details: err.message });
  }
});

// -------------------- Executive tickets list (only own tickets) --------------------

app.get("/api/executive/tickets", requireUser, async (req, res) => {
  try {
    const username = String(req.user.username || "").trim();
    const { ticketNumber } = req.query;

    const conn = await pool.getConnection();
    try {
      let sql = `
        SELECT
          id,
          ticket_number,
          customer_name,
          particulars,
          description,
          due_date,
          created_at,
          status,
          due_duration_text
        FROM tickets
        WHERE username = ?
      `;
      const params = [username];

      if (ticketNumber && String(ticketNumber).trim() !== "") {
        sql += ` AND ticket_number LIKE ? `;
        params.push(`%${String(ticketNumber).trim()}%`);
      }

      sql += ` ORDER BY created_at DESC `;

      const [rows] = await conn.query(sql, params);
      return res.json(rows);
    } finally {
      conn.release();
    }
  } catch (err) {
    return res.status(500).json({ message: "Server error.", details: err.message });
  }
});

app.get("/api/tickets", async (req, res) => {
  try {
    const { ticketNumber } = req.query;

    const conn = await pool.getConnection();
    try {
      let sql = `
        SELECT
          id,
          ticket_number,
          customer_name,
          particulars,
          description,
          due_date,
          created_at,
          status,
          due_duration_text
        FROM tickets
      `;
      const params = [];

      if (ticketNumber && String(ticketNumber).trim() !== "") {
        sql += ` WHERE ticket_number LIKE ? `;
        params.push(`%${String(ticketNumber).trim()}%`);
      }

      sql += ` ORDER BY created_at DESC `;

      const [rows] = await conn.query(sql, params);
      return res.json(rows);
    } finally {
      conn.release();
    }
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Server error.", details: err.message });
  }
});



// -------------------- Admin Auth Helpers --------------------


// -------------------- Admin Auth Routes --------------------

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};
  const ipAddress = getIp(req);
  const userAgent = req.headers["user-agent"] || null;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT id, username, password_hash, is_active
       FROM admin_users
       WHERE username = ?
       LIMIT 1`,
      [username]
    );

    if (!rows.length || !rows[0].is_active) {
      await logAdminAuth({
        adminUserId: null,
        usernameAttempted: username,
        action: "LOGIN_FAIL",
        ipAddress,
        userAgent,
      });
      return res.status(401).json({ message: "Invalid credentials." });
    }

    const admin = rows[0];
    const ok = await bcrypt.compare(password, admin.password_hash);

    if (!ok) {
      await logAdminAuth({
        adminUserId: admin.id,
        usernameAttempted: username,
        action: "LOGIN_FAIL",
        ipAddress,
        userAgent,
      });
      return res.status(401).json({ message: "Invalid credentials." });
    }

    await conn.query(
      `UPDATE admin_users SET last_login_at = NOW() WHERE id = ?`,
      [admin.id]
    );

    await logAdminAuth({
      adminUserId: admin.id,
      usernameAttempted: username,
      action: "LOGIN_SUCCESS",
      ipAddress,
      userAgent,
    });

    const token = signAdminToken({
      adminId: admin.id,
      username: admin.username,
    });
    setAdminCookie(res, token);

    return res.json({ ok: true, username: admin.username });
  } catch (e) {
    console.error("ADMIN_LOGIN_ERROR:", e);
    return res
      .status(500)
      .json({ message: "Server error.", details: e?.message || String(e) });
  } finally {
    conn.release();
  }
});

app.post("/api/admin/logout", requireAdmin, async (req, res) => {
  const ipAddress = getIp(req);
  const userAgent = req.headers["user-agent"] || null;

  await logAdminAuth({
    adminUserId: req.admin?.adminId,
    usernameAttempted: req.admin?.username,
    action: "LOGOUT",
    ipAddress,
    userAgent,
  });

  clearAdminCookie(res);
  return res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, async (req, res) => {
  return res.json({
    ok: true,
    admin: { id: req.admin.adminId, username: req.admin.username },
  });
});

app.post("/api/admin/change-password", requireAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const ipAddress = getIp(req);
  const userAgent = req.headers["user-agent"] || null;

  if (!currentPassword || !newPassword) {
    return res
      .status(400)
      .json({ message: "currentPassword and newPassword required." });
  }
  if (String(newPassword).length < 8) {
    return res
      .status(400)
      .json({ message: "New password must be at least 8 characters." });
  }

  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT id, username, password_hash
       FROM admin_users
       WHERE id = ?
       LIMIT 1`,
      [req.admin.adminId]
    );
    if (!rows.length) return res.status(401).json({ message: "Unauthorized" });

    const admin = rows[0];
    const ok = await bcrypt.compare(currentPassword, admin.password_hash);
    if (!ok) {
      await logAdminAuth({
        adminUserId: admin.id,
        usernameAttempted: admin.username,
        action: "LOGIN_FAIL",
        ipAddress,
        userAgent,
      });
      return res
        .status(401)
        .json({ message: "Current password is incorrect." });
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    await conn.query(`UPDATE admin_users SET password_hash = ? WHERE id = ?`, [
      newHash,
      admin.id,
    ]);

    await logAdminAuth({
      adminUserId: admin.id,
      usernameAttempted: admin.username,
      action: "PASSWORD_CHANGE",
      ipAddress,
      userAgent,
    });

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ message: "Server error." });
  } finally {
    conn.release();
  }
});

app.post("/api/admin/executives", requireAdmin,async (req, res) => {
  try {
    const {
      username,
      password,
      name,
      location,
      exe_mobile_number,
      exe_company_name,
      exe_email,
      area,
      designation,
    } = req.body || {};

    if (
      !username ||
      !password ||
      !name ||
      !location ||
      !exe_mobile_number ||
      !exe_company_name ||
      !exe_email ||
      !area ||
      !designation
    ) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const conn = await pool.getConnection();
    try {
      // check duplicates
      const [existing] = await conn.query(
        "SELECT id FROM users WHERE username = ? OR exe_email = ? LIMIT 1",
        [username, exe_email]
      );
      if (existing.length > 0) {
        return res
          .status(409)
          .json({ message: "Username or email already exists." });
      }

      const password_hash = await bcrypt.hash(password, 10);

      await conn.query(
        `INSERT INTO users
          (username, location, password_hash, name, exe_mobile_number, exe_company_name, exe_email, area, designation)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          username,
          location,
          password_hash,
          name,
          exe_mobile_number,
          exe_company_name,
          exe_email,
          area,
          designation,
        ]
      );

      return res.json({ ok: true });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Add executive failed:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

// 3) IMPORTANT: you must already have this middleware in your project.
// If you don't, add this (simple example) and ensure it matches your admin auth logic:

function requireAdminAuth(req, res, next) {
  // Example: session-based admin login:
  if (req.session?.admin) return next();
  return res.status(401).json({ message: "Unauthorized" });
}

// UPDATE executive
// server.js

app.get("/api/admin/executives", requireAdmin,async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(
        `SELECT id, username, location, name,
                exe_mobile_number, exe_company_name, exe_email, area, designation, created_at
         FROM users
         WHERE (designation = 'Executive' OR LOWER(designation) = 'executive' OR designation IS NULL OR designation = '')
           AND exe_email IS NOT NULL AND exe_email <> ''
         ORDER BY id DESC`
      );
      return res.json({ executives: rows });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("List executives failed:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

app.put("/api/admin/executives/:id", requireAdmin,async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid id." });

    const {
      username,
      name,
      location,
      exe_mobile_number,
      exe_company_name,
      exe_email,
      area,
      password, // optional
    } = req.body || {};

    if (
      !username ||
      !name ||
      !location ||
      !exe_mobile_number ||
      !exe_company_name ||
      !exe_email ||
      !area
    ) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const conn = await pool.getConnection();
    try {
      // ensure executive exists
      const [existing] = await conn.query(
        "SELECT id FROM users WHERE id = ? AND designation = 'Executive' LIMIT 1",
        [id]
      );
      if (existing.length === 0) {
        return res.status(404).json({ message: "Executive not found." });
      }

      // prevent duplicates (username/email) across other users
      const [dup] = await conn.query(
        "SELECT id FROM users WHERE (username = ? OR exe_email = ?) AND id <> ? LIMIT 1",
        [username, exe_email, id]
      );
      if (dup.length > 0) {
        return res
          .status(409)
          .json({ message: "Username or email already exists." });
      }

      if (password && String(password).trim().length > 0) {
        const password_hash = await bcrypt.hash(password, 10);
        await conn.query(
          `UPDATE users
           SET username=?, name=?, location=?,
               exe_mobile_number=?, exe_company_name=?, exe_email=?, area=?,
               password_hash=?,
               designation='Executive'
           WHERE id=?`,
          [
            username,
            name,
            location,
            exe_mobile_number,
            exe_company_name,
            exe_email,
            area,
            password_hash,
            id,
          ]
        );
      } else {
        await conn.query(
          `UPDATE users
           SET username=?, name=?, location=?,
               exe_mobile_number=?, exe_company_name=?, exe_email=?, area=?,
               designation='Executive'
           WHERE id=?`,
          [
            username,
            name,
            location,
            exe_mobile_number,
            exe_company_name,
            exe_email,
            area,
            id,
          ]
        );
      }

      return res.json({ ok: true });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Update executive failed:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

// server.js (ADD THIS) — Report APIs (view + export Excel)
// npm i exceljs

const ExcelJS = require("exceljs");

// Helper: build WHERE clauses safely
function buildReportWhere(q, paramsOut) {
  const where = [];

  // NOTE: adjust join logic if your real mapping differs.
  // Using tickets.username -> users.username as primary linkage.
  if (q.company_name) {
    where.push("t.company_name LIKE ?");
    paramsOut.push(`%${q.company_name}%`);
  }
  if (q.username) {
    // filter either ticket username or user username
    where.push("(t.username LIKE ? OR u.username LIKE ?)");
    paramsOut.push(`%${q.username}%`, `%${q.username}%`);
  }
  if (q.location) {
    where.push("(t.location LIKE ? OR u.location LIKE ?)");
    paramsOut.push(`%${q.location}%`, `%${q.location}%`);
  }
  if (q.customer_name) {
    where.push("t.customer_name LIKE ?");
    paramsOut.push(`%${q.customer_name}%`);
  }
  if (q.category) {
    where.push("t.category LIKE ?");
    paramsOut.push(`%${q.category}%`);
  }
  if (q.request_type) {
    where.push("t.request_type LIKE ?");
    paramsOut.push(`%${q.request_type}%`);
  }
  if (q.status) {
    // requires tickets.status column
    where.push("t.status LIKE ?");
    paramsOut.push(`%${q.status}%`);
  }

  if (q.due_from) {
    where.push("DATE(t.due_date) >= DATE(?)");
    paramsOut.push(q.due_from);
  }
  if (q.due_to) {
    where.push("DATE(t.due_date) <= DATE(?)");
    paramsOut.push(q.due_to);
  }
  if (q.created_from) {
    where.push("DATE(t.created_at) >= DATE(?)");
    paramsOut.push(q.created_from);
  }
  if (q.created_to) {
    where.push("DATE(t.created_at) <= DATE(?)");
    paramsOut.push(q.created_to);
  }

  return where.length ? `WHERE ${where.join(" AND ")}` : "";
}

function reportSelectSQL() {
  // IMPORTANT:
  // - tickets.username exists (per your schema)
  // - users.username exists
  // - tickets.status must exist (you asked to view status). If your column name differs, update it.
  return `
    SELECT
      t.id,
      t.ticket_number,
      t.company_name,
      t.location,
      t.customer_name,
      t.customer_contact_number,
      t.customer_email_id,
      t.category,
      t.request_type,
      t.particulars,
      t.description,
      t.mode_of_payment,
      t.service_charges,
      t.cost,
      t.status,
      t.due_date,
      t.created_at,
      t.username AS ticket_username,

      u.id AS user_id,
      u.username AS user_username,
      u.name AS user_name,
      u.location AS user_location,
      u.exe_mobile_number,
      u.exe_company_name,
      u.exe_email,
      u.area,
      u.designation,
      u.created_at AS user_created_at
    FROM tickets t
    LEFT JOIN users u
      ON u.username = t.username
  `;
}

// 1) VIEW (JSON)
app.get("/api/reports/tickets", async (req, res) => {
  try {
    const q = req.query || {};
    const limit = Math.min(parseInt(q.limit || "200", 10), 2000);

    const params = [];
    const whereSQL = buildReportWhere(q, params);

    const sql = `${reportSelectSQL()} ${whereSQL} ORDER BY t.id DESC LIMIT ?`;
    params.push(limit);

    const [rows] = await pool.query(sql, params);
    return res.json({ rows });
  } catch (err) {
    console.error("REPORT VIEW ERROR:", err);
    return res.status(500).json({ message: "Failed to load report." });
  }
});

// 2) EXPORT (Excel)
app.get("/api/reports/tickets/export", async (req, res) => {
  try {
    const q = req.query || {};
    const params = [];
    const whereSQL = buildReportWhere(q, params);

    const sql = `${reportSelectSQL()} ${whereSQL} ORDER BY t.id DESC`;
    const [rows] = await pool.query(sql, params);

    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet("Tickets Report");

    const columns = [
      { header: "Ticket ID", key: "id", width: 10 },
      { header: "Ticket #", key: "ticket_number", width: 18 },
      { header: "Company", key: "company_name", width: 22 },
      { header: "Location", key: "location", width: 20 },
      { header: "Customer Name", key: "customer_name", width: 20 },
      { header: "Customer Phone", key: "customer_contact_number", width: 18 },
      { header: "Customer Email", key: "customer_email_id", width: 26 },
      { header: "Category", key: "category", width: 16 },
      { header: "Request Type", key: "request_type", width: 16 },
      { header: "Particulars", key: "particulars", width: 22 },
      { header: "Description", key: "description", width: 30 },
      { header: "Payment Mode", key: "mode_of_payment", width: 16 },
      { header: "Service Charges", key: "service_charges", width: 16 },
      { header: "Cost", key: "cost", width: 12 },
      { header: "Status", key: "status", width: 14 },
      { header: "Due Date", key: "due_date", width: 18 },
      { header: "Ticket Created", key: "created_at", width: 18 },
      { header: "Ticket Username", key: "ticket_username", width: 18 },

      { header: "User ID", key: "user_id", width: 10 },
      { header: "User Username", key: "user_username", width: 18 },
      { header: "User Name", key: "user_name", width: 20 },
      { header: "User Location", key: "user_location", width: 20 },
      { header: "Exec Mobile", key: "exe_mobile_number", width: 16 },
      { header: "Exec Company", key: "exe_company_name", width: 22 },
      { header: "Exec Email", key: "exe_email", width: 26 },
      { header: "Area", key: "area", width: 16 },
      { header: "Designation", key: "designation", width: 16 },
      { header: "User Created", key: "user_created_at", width: 18 },
    ];

    ws.columns = columns;

    // Header styling
    ws.getRow(1).font = { bold: true };
    ws.views = [{ state: "frozen", ySplit: 1 }];

    for (const r of rows) {
      ws.addRow(r);
    }

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="tickets_report_${new Date()
        .toISOString()
        .slice(0, 10)}.xlsx"`
    );

    await wb.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error("REPORT EXPORT ERROR:", err);
    return res.status(500).json({ message: "Failed to export report." });
  }
});

// server.js (ADD THIS) — Get ticket by ticket_number + update ticket by ticket_number

app.get("/api/tickets/:ticketNumber", async (req, res) => {
  try {
    const tn = String(req.params.ticketNumber || "").trim();
    if (!tn)
      return res.status(400).json({ message: "ticketNumber is required." });

    const [rows] = await pool.query(
      `SELECT
        id,
        ticket_number,
        company_name,
        location,
        customer_name,
        customer_contact_number,
        customer_email_id,
        category,
        request_type,
        particulars,
        description,
        mode_of_payment,
        service_charges,
        cost,
        due_date,
        created_at,
        status,
        due_duration_text
      FROM tickets
      WHERE ticket_number = ?
      LIMIT 1`,
      [tn]
    );

    if (!rows.length)
      return res.status(404).json({ message: "Ticket not found." });
    return res.json({ ticket: rows[0] });
  } catch (err) {
    console.error("GET TICKET ERROR:", err);
    return res.status(500).json({ message: "Failed to load ticket." });
  }
});

app.put("/api/tickets/:ticketNumber", async (req, res) => {
  try {
    const tn = String(req.params.ticketNumber || "").trim();
    if (!tn)
      return res.status(400).json({ message: "ticketNumber is required." });

    const body = req.body || {};

    const allowed = [
      "company_name",
      "location",
      "customer_name",
      "customer_contact_number",
      "customer_email_id",
      "category",
      "request_type",
      "particulars",
      "description",
      "mode_of_payment",
      "service_charges",
      "cost",
      "due_date",
      "status",
      "due_duration_text",
    ];

    const setParts = [];
    const params = [];

    for (const k of allowed) {
      if (Object.prototype.hasOwnProperty.call(body, k)) {
        setParts.push(`${k} = ?`);
        params.push(body[k]);
      }
    }

    if (!setParts.length) {
      return res.status(400).json({ message: "No valid fields to update." });
    }

    params.push(tn);

    const [result] = await pool.query(
      `UPDATE tickets SET ${setParts.join(", ")} WHERE ticket_number = ?`,
      params
    );

    if (!result.affectedRows) {
      return res.status(404).json({ message: "Ticket not found." });
    }

    const [rows] = await pool.query(
      `SELECT
        id,
        ticket_number,
        company_name,
        location,
        customer_name,
        customer_contact_number,
        customer_email_id,
        category,
        request_type,
        particulars,
        description,
        mode_of_payment,
        service_charges,
        cost,
        due_date,
        created_at,
        status,
        due_duration_text
      FROM tickets
      WHERE ticket_number = ?
      LIMIT 1`,
      [tn]
    );

    return res.json({ message: "Updated", ticket: rows[0] });
  } catch (err) {
    console.error("UPDATE TICKET ERROR:", err);
    return res.status(500).json({ message: "Failed to update ticket." });
  }
});

//Auth

// 1) Start login
app.get("/auth/login", async (req, res) => {
  try {
    const url = await getAuthUrl(req);
    return res.redirect(url);
  } catch (e) {
    console.error("❌ /auth/login error:", e?.message || e);
    return res.status(500).send("Auth login failed. Check server logs.");
  }
});

// 2) Callback
app.get("/auth/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    if (!code) return res.status(400).send("Missing code in callback.");

    await handleAuthCallback(code);

    // You can redirect to any page you want after successful login:
    return res.send("✅ Microsoft login complete. You can close this tab.");
  } catch (e) {
    console.error("❌ /auth/callback error:", e?.message || e);
    return res.status(500).send("Auth callback failed. Check server logs.");
  }
});

/**
 * Operations Users - Admin Only
 */

// CREATE
app.post("/api/admin/operations", requireAdmin, async (req, res) => {
  try {
    const {
      name,
      username,
      mobile_number,
      email,
      password, // ✅ NEW
      remark,
    } = req.body || {};

    if (!name || !username || !mobile_number || !email || !password) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    if (String(password).length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters." });
    }

    const password_hash = await bcrypt.hash(password, 12);

    const conn = await pool.getConnection();
    try {
      await conn.query(
        `INSERT INTO operations_users
         (name, username, mobile_number, email, password_hash, remark, designation)
         VALUES (?, ?, ?, ?, ?, ?, 'Operations')`,
        [
          name.trim(),
          username.trim(),
          String(mobile_number).trim(),
          email.trim(),
          password_hash,
          remark || null,
        ]
      );

      return res.json({ ok: true });
    } finally {
      conn.release();
    }
  } catch (err) {
    if (String(err?.code) === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ message: "Username or email already exists." });
    }
    console.error("ADD_OPERATION_ERROR:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

// LIST (optional but useful for admin view)
app.get("/api/admin/operations", requireAdmin, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(
        `SELECT id, name, username, mobile_number, email, remark, designation, created_at
         FROM operations_users
         ORDER BY id DESC`
      );
      return res.json({ operations: rows });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("LIST_OPERATION_ERROR:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

// UPDATE (optional)
app.put("/api/admin/operations/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid id." });

    const { name, username, mobile_number, email, remark } = req.body || {};

    if (!name || !username || !mobile_number || !email) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const conn = await pool.getConnection();
    try {
      // prevent duplicates across other rows
      const [dup] = await conn.query(
        `SELECT id FROM operations_users
         WHERE (username = ? OR email = ?) AND id <> ? LIMIT 1`,
        [username, email, id]
      );
      if (dup.length)
        return res
          .status(409)
          .json({ message: "Username or email already exists." });

      const [result] = await conn.query(
        `UPDATE operations_users
         SET name=?, username=?, mobile_number=?, email=?, remark=?, designation='Operations'
         WHERE id=?`,
        [
          name.trim(),
          username.trim(),
          String(mobile_number).trim(),
          email.trim(),
          remark || null,
          id,
        ]
      );

      if (!result.affectedRows)
        return res.status(404).json({ message: "Not found." });
      return res.json({ ok: true });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("UPDATE_OPERATION_ERROR:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

app.post("/api/operations/login", async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }

    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(
        `SELECT id, username, name, password_hash
         FROM operations_users
         WHERE username = ?
         LIMIT 1`,
        [username]
      );

      if (!rows || rows.length === 0) {
        return res.status(401).json({ message: "Invalid username or password" });
      }

      const ops = rows[0];
      const ok = await bcrypt.compare(password, ops.password_hash);

      if (!ok) {
        return res.status(401).json({ message: "Invalid username or password" });
      }

      const displayName = String(ops.name || ops.username || "").trim();

      const token = jwt.sign(
        { role: "operations", id: ops.id, name: displayName },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      const isProd = process.env.NODE_ENV === "production";

      // clear old session cookies (match flags)
      res.clearCookie("ops_token", {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
      });
      res.clearCookie("ops_name", {
        httpOnly: false,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
      });

      // set new cookies (use SAME flags for both cookies)
      res.cookie("ops_token", token, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.cookie("ops_name", displayName, {
        httpOnly: false,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      return res.json({ ok: true, name: displayName });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("OPS_LOGIN_ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});


function requireOps(req, res, next) {
  try {
    const token = req.cookies?.ops_token;
    if (!token) return res.status(401).json({ message: "Not logged in" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== "operations") {
      return res.status(403).json({ message: "Forbidden" });
    }

    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid session" });
  }
}

app.get("/api/operations/me", requireOps, (req, res) => {
  return res.json({ id: req.user.id, name: req.user.name });
});

const TICKET_STATUSES = [
  "registered",
  "in_progress",
  "on_hold",
  "completed",
  "closed",
  "cancelled",
  "delayed",
  "reopened",
];

// Allowed statuses (keep in one place)

// Operations/Admin: update status + op_remark
// backend/app.js (or wherever this route is)

// add near your other requires


app.patch("/api/tickets/:ticketNumber/status", async (req, res) => {
  try {
    const tn = String(req.params.ticketNumber || "").trim();
    if (!tn)
      return res.status(400).json({ message: "ticketNumber is required." });

    const status = String(req.body?.status || "").trim();
    const op_remark = String(req.body?.op_remark || "").trim();

    if (!status)
      return res.status(400).json({ message: "status is required." });
    if (!TICKET_STATUSES.includes(status)) {
      return res.status(400).json({ message: "Invalid status." });
    }

    if (
      ["on_hold", "cancelled", "reopened"].includes(status) &&
      op_remark.length < 3
    ) {
      return res
        .status(400)
        .json({ message: "OP remark is required for this status." });
    }

    if (op_remark.length > 2000) {
      return res
        .status(400)
        .json({ message: "OP remark too long (max 2000 chars)." });
    }

    // ✅ 1) Load existing ticket first (for previous status + email fields)
    const [beforeRows] = await pool.query(
      `SELECT
        ticket_number,
        customer_name,
        customer_email_id,
        status
       FROM tickets
       WHERE ticket_number = ?
       LIMIT 1`,
      [tn]
    );

    if (!beforeRows.length) {
      return res.status(404).json({ message: "Ticket not found." });
    }

    const before = beforeRows[0];
    const prevStatus = String(before.status || "").trim();

    // ✅ 2) Update
    const [result] = await pool.query(
      `UPDATE tickets
       SET status = ?, OP_remarks = ?
       WHERE ticket_number = ?`,
      [status, op_remark || null, tn]
    );

    if (!result.affectedRows) {
      return res.status(404).json({ message: "Ticket not found." });
    }

    // ✅ 3) Read updated ticket (your existing response)
    const [rows] = await pool.query(
      `SELECT
        id, ticket_number, customer_name, status, OP_remarks, due_date, created_at
       FROM tickets
       WHERE ticket_number = ?
       LIMIT 1`,
      [tn]
    );

    const updated = rows[0];

    // ✅ 4) Send email ONLY when transitioning to completed
    if (status === "completed" && prevStatus !== "completed") {
      try {
        await sendTicketCompletedEmail({
          to: before.customer_email_id,
          customerName: before.customer_name,
          ticketNumber: before.ticket_number,
          opRemark: op_remark || "",
        });
      } catch (mailErr) {
        console.error("❌ COMPLETED MAIL FAILED:", mailErr?.message || mailErr);
        // do not fail status update if mail fails
      }
    }

    return res.json({ ok: true, ticket: updated });
  } catch (err) {
    console.error("STATUS UPDATE ERROR:", err);
    return res.status(500).json({ message: "Failed to update status." });
  }
});
