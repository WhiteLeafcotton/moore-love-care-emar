
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const pg = require("pg");
const PgSession = require("connect-pg-simple")(session);
const nodemailer = require("nodemailer");
const argon2 = require("argon2");
const crypto = require("crypto");
const QRCode = require("qrcode");
const { authenticator } = require("otplib");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: true }
    : undefined
});

app.use(helmet());
app.use(express.json({ limit: "10kb" }));

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use(session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  name: "moore_emar_session",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000
  }
}));

const setupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const codeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  }
});

const randomCode = () =>
  crypto.randomInt(100000, 1000000).toString();

const hashCode = code =>
  crypto.createHmac("sha256", process.env.OTP_PEPPER)
    .update(code)
    .digest("hex");

const safeCompare = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length &&
    crypto.timingSafeEqual(x, y);
};

function encryptSecret(secret) {
  const key = Buffer.from(
    process.env.MFA_ENCRYPTION_KEY, "hex"
  );

  if (key.length !== 32) {
    throw new Error("MFA encryption key must be 32 bytes.");
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(secret, "utf8"),
    cipher.final()
  ]);

  return [
    iv.toString("hex"),
    cipher.getAuthTag().toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decryptSecret(value) {
  const [iv, tag, encrypted] = value.split(":");
  const key = Buffer.from(
    process.env.MFA_ENCRYPTION_KEY, "hex"
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(iv, "hex")
  );

  decipher.setAuthTag(Buffer.from(tag, "hex"));

  return Buffer.concat([
    decipher.update(Buffer.from(encrypted, "hex")),
    decipher.final()
  ]).toString("utf8");
}

async function getSetup(req) {
  if (!req.session.setupId) return null;

  const result = await pool.query(
    `SELECT * FROM manager_setup
     WHERE id = $1
     AND verification_expires > NOW()`,
    [req.session.setupId]
  );

  return result.rows[0] || null;
}

function requireSetup(req, res, next) {
  if (!req.session.setupId) {
    return res.status(401).json({
      error: "Enrollment session expired."
    });
  }
  next();
}

// STEP 1-3:
// Verify initial enrollment authorization and email a code.

app.post(
  "/api/setup/start",
  setupLimiter,
  async (req, res) => {
    try {
      const { username, email, setupKey } = req.body;

      if (username !== "1234") {
        return res.status(400).json({
          error: "Invalid manager username."
        });
      }

      if (
        !email ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      ) {
        return res.status(400).json({
          error: "Enter a valid company email."
        });
      }

      const configuredKey = process.env.BOOTSTRAP_SETUP_KEY;

      if (
        !configuredKey ||
        !setupKey ||
        !safeCompare(setupKey, configuredKey)
      ) {
        return res.status(403).json({
          error: "Enrollment authorization failed."
        });
      }

      const existing = await pool.query(
        "SELECT id FROM managers LIMIT 1"
      );

      if (existing.rowCount > 0) {
        return res.status(403).json({
          error: "Initial enrollment is already completed."
        });
      }

      const code = randomCode();
      const verificationHash = hashCode(code);

      const result = await pool.query(
        `INSERT INTO manager_setup
          (username, email, verification_hash,
           verification_expires)
         VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')
         RETURNING id`,
        ["1234", email.toLowerCase(), verificationHash]
      );

      req.session.setupId = result.rows[0].id;

      await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: "Moore Love & Care - Email Verification",
        text: `Your verification code is ${code}. 
It expires in 10 minutes. If you did not request this, ignore this email.`,
      });

      res.json({
        success: true,
        message: "Verification code sent."
      });

    } catch (error) {
      console.error("Setup start failed:", error.message);
      res.status(500).json({
        error: "Unable to start enrollment."
      });
    }
  }
);

// STEP 4: Verify email ownership.

app.post(
  "/api/setup/verify-email",
  requireSetup,
  codeLimiter,
  async (req, res) => {
    try {
      const { code } = req.body;
      const setup = await getSetup(req);

      if (!setup || setup.verified_at) {
        return res.status(400).json({
          error: "Verification session is invalid."
        });
      }

      if (
        !code ||
        !/^\d{6}$/.test(code) ||
        !safeCompare(hashCode(code), setup.verification_hash)
      ) {
        return res.status(400).json({
          error: "Invalid verification code."
        });
      }

      await pool.query(
        `UPDATE manager_setup
         SET verified_at = NOW()
         WHERE id = $1`,
        [setup.id]
      );

      res.json({
        success: true,
        message: "Email verified."
      });

    } catch (error) {
      console.error(error.message);
      res.status(500).json({
        error: "Email verification failed."
      });
    }
  }
);

// STEP 5: Create manager password.

app.post(
  "/api/setup/create-password",
  requireSetup,
  async (req, res) => {
    try {
      const { password, confirmPassword } = req.body;
      const setup = await getSetup(req);

      if (!setup || !setup.verified_at) {
        return res.status(403).json({
          error: "Verify your email first."
        });
      }

      if (
        typeof password !== "string" ||
        password.length < 12 ||
        password.length > 128
      ) {
        return res.status(400).json({
          error: "Password must be 12-128 characters."
        });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({
          error: "Passwords do not match."
        });
      }

      const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id
      });

      await pool.query(
        `UPDATE manager_setup
         SET password_hash = $1
         WHERE id = $2`,
        [passwordHash, setup.id]
      );

      res.json({
        success: true,
        message: "Password created. Enroll in MFA next."
      });

    } catch (error) {
      console.error(error.message);
      res.status(500).json({
        error: "Password creation failed."
      });
    }
  }
);

// STEP 6A: Generate authenticator enrollment QR code.

app.post(
  "/api/setup/mfa",
  requireSetup,
  async (req, res) => {
    try {
      const setup = await getSetup(req);

      if (!setup || !setup.password_hash) {
        return res.status(403).json({
          error: "Create your password first."
        });
      }

      const secret = authenticator.generateSecret();

      const uri = authenticator.keyuri(
        setup.email,
        "Moore Love & Care eMAR",
        secret
      );

      const qrCode = await QRCode.toDataURL(uri);

      await pool.query(
        `UPDATE manager_setup
         SET mfa_secret_encrypted = $1
         WHERE id = $2`,
        [encryptSecret(secret), setup.id]
      );

      res.json({
        qrCode,
        manualSecret: secret,
        message: "Scan with your authenticator app."
      });

    } catch (error) {
      console.error(error.message);
      res.status(500).json({
        error: "Unable to initialize MFA."
      });
    }
  }
);

// STEP 6B-7: Confirm MFA and activate account.

app.post(
  "/api/setup/mfa/confirm",
  requireSetup,
  codeLimiter,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const { code } = req.body;
      const setup = await getSetup(req);

      if (
        !setup ||
        !setup.password_hash ||
        !setup.mfa_secret_encrypted
      ) {
        return res.status(403).json({
          error: "Complete the previous setup steps."
        });
      }

      const secret = decryptSecret(
        setup.mfa_secret_encrypted
      );

      const valid = authenticator.verify({
        token: code,
        secret
      });

      if (!valid) {
        return res.status(400).json({
          error: "Invalid authenticator code."
        });
      }

      await client.query("BEGIN");

      const manager = await client.query(
        `INSERT INTO managers
          (username, email, password_hash,
           mfa_secret_encrypted, role, account_status)
         VALUES ($1, $2, $3, $4, 'owner', 'active')
         RETURNING id, username, role`,
        [
          setup.username,
          setup.email,
          setup.password_hash,
          setup.mfa_secret_encrypted
        ]
      );

      await client.query(
        "DELETE FROM manager_setup WHERE id = $1",
        [setup.id]
      );

      await client.query("COMMIT");

      await new Promise((resolve, reject) => {
        req.session.regenerate(err =>
          err ? reject(err) : resolve()
        );
      });

      req.session.managerId = manager.rows[0].id;

      res.json({
        success: true,
        message: "Manager account activated.",
        manager: manager.rows[0]
      });

    } catch (error) {
      await client.query("ROLLBACK");
      console.error(error.message);

      res.status(500).json({
        error: "MFA activation failed."
      });

    } finally {
      client.release();
    }
  }
);

// Protected manager dashboard test endpoint.

app.get("/api/manager/me", async (req, res) => {
  if (!req.session.managerId) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  const result = await pool.query(
    `SELECT id, username, role, account_status
     FROM managers
     WHERE id = $1 AND account_status = 'active'`,
    [req.session.managerId]
  );

  if (!result.rowCount) {
    return res.status(401).json({
      error: "Manager account unavailable."
    });
  }

  res.json({ manager: result.rows[0] });
});

app.listen(process.env.PORT || 3001, () => {
  console.log("Moore Love & Care eMAR API started.");
});

