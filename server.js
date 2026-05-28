const express = require("express");
const { connectDB, sql } = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");
const supabase = require("./supabaseClient");
const app = express();
app.use(express.json());

// ✅ SERVE FRONTEND
app.use(express.static(path.join(__dirname, "public")));

connectDB();

// ✅ REGISTER USER
app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const { error } = await supabase
        .from("users")
        .insert([{ email, password: hashedPassword }]);

    if (error) {
        return res.json({ message: "Registration error ❌ " + error.message });
    }

    res.json({ message: "User registered successfully ✅" });
});

// ✅ LOGIN USER
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .single();

    if (error || !data) {
        return res.json({ message: "User not found ❌" });
    }

    const isMatch = await bcrypt.compare(password, data.password);

    if (!isMatch) {
        return res.json({ message: "Wrong password ❌" });
    }

    const token = jwt.sign(
        { id: data.id, email: data.email },
        "SECRET_KEY",
        { expiresIn: "1h" }
    );

    res.json({
        message: "Login successful ✅",
        token
    });
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

        if (!file) {
            return res.json({ message: "No file uploaded ❌" });
        }

        // 1. Read uploaded file
        const fileData = fs.readFileSync(file.path);

        // 2. Encrypt file
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(fileData);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        // 3. Basic temporary risk analysis until AI API is added
        const originalName = file.originalname.toLowerCase();
        let risk_level = "LOW";
        let risk_score = 20;
        let risk_reason = "Safe document type detected";

        if (
            originalName.includes(".exe") ||
            originalName.includes(".bat") ||
            originalName.includes(".js") ||
            originalName.includes("malware") ||
            originalName.includes("virus")
        ) {
            risk_level = "HIGH";
            risk_score = 90;
            risk_reason = "Executable/script or suspicious keyword detected";
        } else if (
            originalName.includes(".zip") ||
            originalName.includes(".rar") ||
            originalName.includes(".docm")
        ) {
            risk_level = "MEDIUM";
            risk_score = 60;
            risk_reason = "Compressed or macro-enabled file detected";
        }

        // 4. Upload encrypted file to Supabase Storage
        const cloudFilePath = `${req.user.id}/${Date.now()}-${file.originalname}.enc`;

        const { error: uploadError } = await supabase.storage
            .from("encrypted-files")
            .upload(cloudFilePath, encrypted, {
                contentType: "application/octet-stream",
                upsert: false
            });

        if (uploadError) {
            return res.json({ message: "Supabase storage error ❌ " + uploadError.message });
        }

        // 5. Save file metadata to Supabase database
        const { error: dbError } = await supabase
            .from("files")
            .insert([{
                user_id: req.user.id,
                filename: file.originalname + ".enc",
                file_path: cloudFilePath,
                risk_level,
                risk_score,
                risk_reason,
                encrypted: true
            }]);

        if (dbError) {
            return res.json({ message: "Database save error ❌ " + dbError.message });
        }

        // 6. Remove temporary local file
        fs.unlinkSync(file.path);

        // 7. Send analysis result to frontend
        res.json({
            message: "File encrypted, analyzed and uploaded to cloud successfully ✅",
            filename: file.originalname,
            risk_level,
            risk_score,
            risk_reason
        });

    } catch (err) {
        res.json({ message: "Upload error ❌ " + err.message });
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
    const { data, error } = await supabase
        .from("files")
        .select("*")
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false });

    if (error) return res.json([]);

    res.json(data);
});
// 🚀 START SERVER
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});