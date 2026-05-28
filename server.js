const express = require("express");
const { connectDB, sql } = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(express.json());

// ✅ SERVE FRONTEND
app.use(express.static(path.join(__dirname, "public")));

connectDB();

// ✅ REGISTER USER
app.post("/register", async (req, res) => {
    res.json({ message: "Cloud demo mode: registration is disabled. Use test@test.com / 123456" });
});

app.post("/register", async (req, res) => {
    res.json({ message: "Cloud demo mode: registration is disabled. Use test@test.com / 123456" });
});

// 🔐 AUTH MIDDLEWARE
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.send("No token provided ❌");
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, "SECRET_KEY", (err, user) => {
        if (err) return res.send("Invalid token ❌");

        req.user = user;
        next();
    });
};

// ✅ DASHBOARD
app.get("/dashboard", authenticateToken, (req, res) => {
    res.send("Welcome " + req.user.email + " 🔐");
});

// 📦 FILE UPLOAD SETUP
const multer = require("multer");

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads/");
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    }
});

const upload = multer({ storage });

// 🔐 ENCRYPTION
const crypto = require("crypto");
const fs = require("fs");

const algorithm = "aes-256-cbc";
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// ✅ FIXED UPLOAD ROUTE (IMPORTANT)
app.post("/upload", authenticateToken, upload.single("file"), async (req, res) => {
    try {
        const file = req.file;

        const fileData = fs.readFileSync(file.path);

        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(fileData);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        const encryptedPath = file.path + ".enc";
        fs.writeFileSync(encryptedPath, encrypted);

        fs.unlinkSync(file.path);

        // ✅ FIX: use real user id
        await sql.query(`
            INSERT INTO Files (user_id, filename, filepath)
            VALUES (${req.user.id}, '${file.filename}.enc', '${encryptedPath}')
        `);

        res.send("File encrypted & uploaded securely 🔐");

    } catch (err) {
        res.send("Error ❌ " + err);
    }
});

// 📄 SIMPLE UPLOAD PAGE (optional)
app.get("/upload-page", (req, res) => {
    res.send(`
        <h2>Upload File</h2>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" />
            <button type="submit">Upload</button>
        </form>
    `);
});

// ⚠️ ANOMALY DETECTION
let uploadCount = {};

app.post("/upload-limit", authenticateToken, upload.single("file"), (req, res) => {
    const userId = req.user.id;

    if (!uploadCount[userId]) uploadCount[userId] = 0;

    uploadCount[userId]++;

    if (uploadCount[userId] > 5) {
        console.log("⚠️ Suspicious activity detected for user:", userId);
    }

    res.send("Upload processed ✅");
});
app.get("/files", authenticateToken, async (req, res) => {
    res.json([
        { filename: "company_policy.pdf.enc" },
        { filename: "backup_archive.zip.enc" },
        { filename: "unknown_script.js.enc" },
        { filename: "employee_report.docx.enc" },
        { filename: "setup_file.exe.enc" }
    ]);
});

// 🚀 START SERVER
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});