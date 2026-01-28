// backend/scripts/seed_admin.js

require("dotenv").config({ path: require("path").resolve(__dirname, "../.env") });

const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");

(async () => {
  const username = process.argv[2];
  const password = process.argv[3];

  if (!username || !password) {
    console.error("Usage: node seed_admin.js <username> <password>");
    process.exit(1);
  }

  const required = ["DB_HOST", "DB_USER", "DB_PASS", "DB_NAME"];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    console.error("Missing DB env vars in backend/.env:", missing.join(", "));
    console.error(
      "Add these to backend/.env:\nDB_HOST=...\nDB_USER=...\nDB_PASS=...\nDB_NAME=...\n"
    );
    process.exit(1);
  }

  const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
  });

  try {
    const hash = await bcrypt.hash(password, 12);

    await pool.execute(
      `INSERT INTO admin_users (username, password_hash, is_active)
       VALUES (?, ?, 1)
       ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), is_active = 1`,
      [username.trim(), hash]
    );

    console.log("Admin upserted:", username.trim());
  } catch (e) {
    console.error("Seed failed:", e.message);
    process.exit(1);
  } finally {
    await pool.end();
    process.exit(0);
  }
})();
