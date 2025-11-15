"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// src/index.ts
const express_1 = __importStar(require("express"));
const client_1 = require("@prisma/client");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const nodemailer_1 = __importDefault(require("nodemailer"));
const cors_1 = __importDefault(require("cors"));
const express_session_1 = __importDefault(require("express-session"));
const passport_1 = __importDefault(require("passport"));
const passport_google_oauth20_1 = require("passport-google-oauth20");
const passport_github2_1 = require("passport-github2");
const node_fetch_1 = __importDefault(require("node-fetch"));
const app = (0, express_1.default)();
const prisma = new client_1.PrismaClient();
const router = (0, express_1.Router)();
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
// ----------------- CORS -----------------
const allowedOrigins = ["http://localhost:3000", "https://bildare.vercel.app"];
app.use((0, cors_1.default)({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin))
            return callback(null, true);
        return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
}));
// ----------------- Session -----------------
const isProduction = process.env.NODE_ENV === "production";
app.set("trust proxy", 1);
app.use((0, express_session_1.default)({
    name: process.env.SESSION_COOKIE_NAME || "sid",
    secret: process.env.SESSION_SECRET || "sessionsecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    },
}));
// ----------------- Passport -----------------
app.use(passport_1.default.initialize());
// ----------------- Email Transporter -----------------
const transporter = nodemailer_1.default.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});
// ----------------- JWT Helpers -----------------
const SECRET_KEY = process.env.JWT_SECRET || "supersecret";
const REFRESH_SECRET_KEY = process.env.JWT_REFRESH_SECRET || SECRET_KEY;
const generateAccessToken = (userId) => jsonwebtoken_1.default.sign({ userId }, SECRET_KEY, { expiresIn: "1h" });
const generateRefreshToken = (userId) => jsonwebtoken_1.default.sign({ userId }, REFRESH_SECRET_KEY, { expiresIn: "7d" });
// ----------------- OTP Email Helper -----------------
const sendOtpEmail = async (email, otp) => {
    try {
        await transporter.sendMail({
            from: `"Bildare Auth" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "🔐 Your Bildare Verification Code",
            text: `Hello,\n\nYour One-Time Password (OTP) is: ${otp}\n\nPlease use this code to verify your email. It will expire in 10 minutes.\n\nThank you,\nThe Bildare Team`,
            html: `
      <div style="font-family: Arial, sans-serif; line-height:1.5; color:#333;">
        <h2>Welcome to <span style="color:#ff510d;">Bildare</span> 🎉</h2>
        <p>We are excited to have you on board! To complete your sign up, please verify your email using the OTP below:</p>
        <div style="margin:20px 0; padding:15px; background:#f4f4f4; border-radius:8px; text-align:center;">
          <h1 style="color:#182a4e; letter-spacing:5px;">${otp}</h1>
        </div>
        <p>This code will expire in <b>10 minutes</b>. If you did not request this, please ignore this email.</p>
        <p style="margin-top:30px;">Cheers,<br><b>The Bildare Team</b></p>
      </div>
    `,
        });
        console.log("✅ OTP email sent to", email);
    }
    catch (err) {
        console.error("❌ Failed to send OTP email:", err);
    }
};
// ----------------- Logging -----------------
app.use((req, res, next) => {
    console.log(`Incoming request: ${req.method} ${req.url}`);
    next();
});
// ----------------- Google OAuth (Prisma) -----------------
passport_1.default.use(new passport_google_oauth20_1.Strategy({
    clientID: process.env.GOOGLE_CLIENT_ID || "",
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
    callbackURL: isProduction
        ? "https://bildare-backend.onrender.com/auth/google/callback"
        : "http://localhost:5000/auth/google/callback",
}, async (accessToken, refreshToken, profile, done) => {
    var _a, _b;
    try {
        const email = (_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.value;
        if (!email)
            return done(new Error("Email not provided by Google"));
        // Find or create user
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            user = await prisma.user.create({
                data: {
                    username: profile.displayName || profile.id,
                    email,
                    is_verified: true,
                    region: "Unknown",
                    interests: [],
                },
            });
        }
        // Generate JWT tokens
        const access = generateAccessToken(user.user_id);
        const refresh = generateRefreshToken(user.user_id);
        // Hash refresh token before storing
        const hashedRefresh = await bcryptjs_1.default.hash(refresh, 10);
        // Store hashed refresh token in Prisma
        user = await prisma.user.update({
            where: { user_id: user.user_id },
            data: { refresh_token: hashedRefresh },
        });
        done(null, { ...user, accessToken: access, refreshToken: refresh });
    }
    catch (err) {
        done(err);
    }
}));
// ----------------- Passport GitHub Strategy -----------------
passport_1.default.use(new passport_github2_1.Strategy({
    clientID: process.env.GITHUB_CLIENT_ID || "",
    clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
    callbackURL: isProduction
        ? "https://bildare-backend.onrender.com/auth/github/callback"
        : "http://localhost:5000/auth/github/callback",
    scope: ["user:email"],
}, async (accessToken, refreshToken, profile, done) => {
    var _a, _b;
    try {
        const email = (_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.value;
        if (!email)
            return done(new Error("GitHub email not available"));
        // Find or create user
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            user = await prisma.user.create({
                data: {
                    username: profile.displayName || profile.username,
                    email,
                    is_verified: true,
                    region: "Unknown",
                    interests: [],
                },
            });
        }
        // Generate JWT tokens
        const access = generateAccessToken(user.user_id);
        const refresh = generateRefreshToken(user.user_id);
        // Hash refresh token before storing
        const hashedRefresh = await bcryptjs_1.default.hash(refresh, 10);
        // Store hashed refresh token in Prisma
        user = await prisma.user.update({
            where: { user_id: user.user_id },
            data: { refresh_token: hashedRefresh },
        });
        done(null, { ...user, accessToken: access, refreshToken: refresh });
    }
    catch (err) {
        done(err);
    }
}));
// -----------------  Routes -----------------
router.post("/signup", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ error: "Email and password are required" });
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser)
            return res.status(400).json({ error: "Email already registered" });
        const hashedPassword = await bcryptjs_1.default.hash(password, 10);
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
        await prisma.user.create({
            data: {
                email,
                password_hash: hashedPassword,
                username: email.split("@")[0],
                is_verified: false,
                region: "Unknown",
                interests: [],
                otp,
                otp_expires: otpExpires,
            },
        });
        sendOtpEmail(email, otp); // send OTP but don't block signup if email fails
        res.json({
            message: "OTP sent to email. Please verify within 10 minutes.",
            email,
        });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- 🔁 Resend OTP -----------------
router.post("/resend-otp", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email)
            return res.status(400).json({ error: "Email is required" });
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(400).json({ error: "User not found" });
        if (user.is_verified)
            return res.status(400).json({ error: "Already verified" });
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
        await prisma.user.update({
            where: { email },
            data: {
                otp,
                otp_expires: otpExpires,
            },
        });
        sendOtpEmail(email, otp);
        res.json({
            message: "New OTP sent to email. Please verify within 10 minutes.",
        });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- 2️⃣ Verify OTP -----------------
router.post("/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp)
            return res.status(400).json({ error: "Email and OTP are required" });
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(400).json({ error: "User not found" });
        if (user.is_verified)
            return res.status(400).json({ error: "Already verified" });
        // If OTP expired or invalid (if you stored OTP)
        if (!user.otp || !user.otp_expires || new Date() > user.otp_expires) {
            return res.status(400).json({ error: "OTP has expired. Please request a new one." });
        }
        if (user.otp !== otp)
            return res.status(400).json({ error: "Invalid OTP" });
        await prisma.user.update({
            where: { email },
            data: {
                is_verified: true,
                // otp: null,
                // otpExpires: null,
            },
        });
        res.json({ message: "OTP verified. Now complete your profile." });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- 3️⃣ Complete Profile -----------------
router.post("/complete-profile", async (req, res) => {
    var _a, _b;
    try {
        const { email, username, role, region, interests } = req.body;
        if (!email || !username || !role || !region) {
            return res.status(400).json({ error: "Email, username, role, and region are required" });
        }
        // Fetch user
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(404).json({ error: "User not found" });
        if (!user.is_verified)
            return res.status(400).json({ error: "Email not verified" });
        // Generate JWTs
        const accessToken = generateAccessToken(user.user_id);
        const refreshToken = generateRefreshToken(user.user_id);
        // Hash refresh token before storing
        const hashedRefresh = await bcryptjs_1.default.hash(refreshToken, 10);
        // Update user profile in Prisma
        user = await prisma.user.update({
            where: { user_id: user.user_id },
            data: {
                username,
                role, // save role
                region,
                interests, // save interests array
                refresh_token: hashedRefresh,
            },
        });
        // Save user session
        req.session.user = {
            id: user.user_id,
            email: user.email,
            username: user.username,
            role: (_a = user.role) !== null && _a !== void 0 ? _a : undefined,
            region: (_b = user.region) !== null && _b !== void 0 ? _b : undefined,
            interests: user.interests,
            accessToken,
            refreshToken,
        };
        return res.json({
            message: "Profile completed successfully!",
            user: req.session.user,
        });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Server error" });
    }
});
// ----------------- 4️⃣ Login -----------------
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ error: "Email and password are required" });
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(404).json({ error: "User not found" });
        if (!user.is_verified)
            return res.status(400).json({ error: "Email not verified" });
        // Check password
        const valid = await bcryptjs_1.default.compare(password, user.password_hash || "");
        if (!valid)
            return res.status(400).json({ error: "Invalid password" });
        // Generate JWTs
        const accessToken = generateAccessToken(user.user_id);
        const refreshToken = generateRefreshToken(user.user_id);
        // Hash refresh token before storing
        const hashedRefresh = await bcryptjs_1.default.hash(refreshToken, 10);
        // Update refresh_token in Prisma
        await prisma.user.update({
            where: { user_id: user.user_id },
            data: { refresh_token: hashedRefresh },
        });
        // Save user session
        req.session.user = {
            id: user.user_id,
            email: user.email,
            username: user.username,
            interests: user.interests,
            accessToken,
            refreshToken,
        };
        return res.json({
            message: "Login successful",
            user: req.session.user,
        });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Server error" });
    }
});
// ----------------- /me -----------------
router.get("/me", (req, res) => {
    const sessionUser = req.session.user;
    if (!sessionUser)
        return res.status(401).json({ error: "Not authenticated" });
    const { id, email, username, interests, accessToken, refreshToken } = sessionUser;
    res.json({ id, email, username, interests, accessToken, refreshToken });
});
// ----------------- Logout -----------------
router.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Failed to destroy session:", err);
            return res.status(500).json({ error: "Logout failed" });
        }
        res.clearCookie(process.env.SESSION_COOKIE_NAME || "sid");
        res.json({ message: "Logged out successfully" });
    });
});
// ----------------- Protected /profile -----------------
router.get("/profile", async (req, res) => {
    try {
        if (!req.session.user)
            return res.status(401).json({ error: "Not authenticated" });
        const user = await prisma.user.findUnique({ where: { user_id: req.session.user.id } });
        if (!user)
            return res.status(404).json({ error: "User not found" });
        res.json({ message: `Welcome ${user.email}`, region: user.region, interests: user.interests });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- Refresh Access Token -----------------
router.post("/token", async (req, res) => {
    var _a;
    try {
        const sessionToken = (_a = req.session.user) === null || _a === void 0 ? void 0 : _a.refreshToken;
        const bodyToken = req.body.refreshToken;
        const refreshToken = sessionToken || bodyToken;
        if (!refreshToken)
            return res.status(401).json({ error: "Refresh token required" });
        const user = await prisma.user.findFirst({
            where: { refresh_token: refreshToken },
        });
        if (!user)
            return res.status(403).json({ error: "Invalid refresh token" });
        jsonwebtoken_1.default.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || "secret", (err) => {
            if (err)
                return res.status(403).json({ error: "Invalid refresh token" });
            const accessToken = generateAccessToken(user.user_id);
            if (req.session.user)
                req.session.user.accessToken = accessToken;
            res.json({ accessToken });
        });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- Request Password Reset -----------------
router.post("/request-password-reset", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email)
            return res.status(400).json({ error: "Email is required" });
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(404).json({ error: "User not found" });
        const token = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 15 * 60 * 1000);
        await prisma.user.update({
            where: { email },
            data: { reset_password_token: token, reset_password_expires: expires },
        });
        await transporter.sendMail({
            from: `"Bildare Auth" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Password Reset Request",
            text: `Use this token to reset your password: ${token}\nExpires in 15 minutes.`,
        });
        res.json({ message: "Password reset token sent to email." });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- Verify Reset Token -----------------
router.post("/verify-reset-token", async (req, res) => {
    try {
        const { email, token } = req.body;
        if (!email || !token)
            return res.status(400).json({ error: "Email and token are required" });
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(404).json({ error: "User not found" });
        if (user.reset_password_token !== token || !user.reset_password_expires || new Date() > user.reset_password_expires) {
            return res.status(400).json({ error: "Invalid or expired token" });
        }
        res.json({ message: "Token is valid. You can now reset your password." });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- Reset Password -----------------
router.post("/reset-password", async (req, res) => {
    try {
        const { email, token, newPassword } = req.body;
        if (!email || !token || !newPassword)
            return res.status(400).json({ error: "All fields are required" });
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user)
            return res.status(404).json({ error: "User not found" });
        if (user.reset_password_token !== token || !user.reset_password_expires || new Date() > user.reset_password_expires) {
            return res.status(400).json({ error: "Invalid or expired token" });
        }
        const hashedPassword = await bcryptjs_1.default.hash(newPassword, 10);
        await prisma.user.update({
            where: { email },
            data: {
                password_hash: hashedPassword,
                reset_password_token: null,
                reset_password_expires: null,
            },
        });
        res.json({ message: "Password reset successfully!" });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- Fetch All Users -----------------
router.get("/users", async (_req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                user_id: true,
                email: true,
                username: true,
                interests: true,
                is_verified: true,
            },
        });
        res.json(users);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- Delete User -----------------
router.delete("/users", async (req, res) => {
    try {
        const { id } = req.body;
        if (!id)
            return res.status(400).json({ error: "User ID is required" });
        const deleted = await prisma.user.delete({ where: { user_id: id } });
        res.json({ message: "User deleted successfully", id: deleted.user_id });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
});
// ----------------- /active-users -----------------
// router.get("/active-users", (req: Request, res: Response) => {
//   const store = req.sessionStore;
//   if (!store) {
//     return res.status(500).json({ error: "Session store not found" });
//   }
//   // Type assertion: tell TS that store.all exists
//   (store.all as (callback: (err: any, sessions: { [sid: string]: Express.SessionDat }) => void) => void)(
//     (err, sessions) => {
//       if (err) {
//         console.error("Error fetching sessions:", err);
//         return res.status(500).json({ error: "Could not fetch active users" });
//       }
//       const users: { email: string; username?: string; interests?: any; role?: string; }[] = [];
//       for (const sid in sessions) {
//         const session = sessions[sid];
//         if (session?.user) {
//           users.push({
//             email: session.user.email,
//             username: session.user.username,
//             interests: session.user.interests,
//             role: session.user.role,
//           });
//         }
//       }
//       res.json({
//         activeCount: users.length,
//         activeUsers: users,
//       });
//     }
//   );
// });
// ----------------- Google OAuth -----------------
router.get("/auth/google", passport_1.default.authenticate("google", { scope: ["profile", "email"] }));
router.get("/auth/google/callback", passport_1.default.authenticate("google", { failureRedirect: "/auth", session: false }), async (req, res) => {
    try {
        const userData = req.user;
        // Upsert user in DB
        const user = await prisma.user.upsert({
            where: { email: userData.email },
            update: {
                username: userData.username || userData.email.split("@")[0],
                refresh_token: await bcryptjs_1.default.hash(userData.refreshToken, 10),
            },
            create: {
                email: userData.email,
                username: userData.username || userData.email.split("@")[0],
                is_verified: true,
                region: "Unknown",
                interests: [],
                refresh_token: await bcryptjs_1.default.hash(userData.refreshToken, 10),
            },
        });
        req.session.user = {
            id: user.user_id,
            email: user.email,
            username: user.username,
            accessToken: userData.accessToken,
            refreshToken: userData.refreshToken,
        };
        res.redirect("https://bildare.vercel.app/");
    }
    catch (err) {
        console.error(err);
        res.status(500).send("OAuth login failed");
    }
});
// ----------------- GitHub OAuth -----------------
router.get("/auth/github", passport_1.default.authenticate("github"));
router.get("/auth/github/callback", passport_1.default.authenticate("github", { failureRedirect: "/auth", session: false }), async (req, res) => {
    try {
        const userData = req.user;
        // Upsert user in DB
        const user = await prisma.user.upsert({
            where: { email: userData.email },
            update: {
                username: userData.username || userData.email.split("@")[0],
                refresh_token: await bcryptjs_1.default.hash(userData.refreshToken, 10),
            },
            create: {
                email: userData.email,
                username: userData.username || userData.email.split("@")[0],
                is_verified: true,
                region: "Unknown",
                interests: [],
                refresh_token: await bcryptjs_1.default.hash(userData.refreshToken, 10),
            },
        });
        req.session.user = {
            id: user.user_id,
            email: user.email,
            username: user.username,
            accessToken: userData.accessToken,
            refreshToken: userData.refreshToken,
        };
        res.redirect("https://bildare.vercel.app/");
    }
    catch (err) {
        console.error(err);
        res.status(500).send("OAuth login failed");
    }
});
// ----------------- Contact form -----------------
router.post("/contact", async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        if (!name || !email || !subject || !message) {
            return res.status(400).json({ error: "All fields are required." });
        }
        const mailOptions = {
            from: `"Bildare Website Contact" <${process.env.EMAIL_USER}>`,
            to: "bildare.auth@gmail.com",
            subject: `📩 New Contact Form Submission: ${subject}`,
            html: `
        <div style="margin:0; padding:0; font-family: 'Helvetica', Arial, sans-serif; background-color:#f4f4f4;">
          <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:auto; background:#ffffff; border-radius:12px; overflow:hidden; box-shadow:0 0 10px rgba(0,0,0,0.1);">
            <tr>
              <td style="background-color:#B9F500; text-align:center; padding:20px;">
                <h1 style="margin:0; font-size:24px; color:#000;">Bildare Contact Form</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:20px; color:#333;">
                <p style="margin:0 0 10px;"><strong>Name:</strong> ${name}</p>
                <p style="margin:0 0 10px;"><strong>Email:</strong> ${email}</p>
                <p style="margin:0 0 10px;"><strong>Subject:</strong> ${subject}</p>
                <p style="margin:20px 0 5px;"><strong>Message:</strong></p>
                <div style="padding:15px; background:#f9f9f9; border-radius:8px; color:#555; line-height:1.5;">
                  ${message.replace(/\n/g, "<br>")}
                </div>
              </td>
            </tr>
            <tr>
              <td style="padding:20px; text-align:center; font-size:12px; color:#888;">
                This message was sent from the Bildare website contact form.
              </td>
            </tr>
          </table>
        </div>
      `,
        };
        await transporter.sendMail(mailOptions);
        res.json({ message: "Your message has been sent successfully!" });
    }
    catch (err) {
        console.error("Error sending contact email:", err);
        res.status(500).json({ error: "Failed to send message." });
    }
});
// ----------------- Root -----------------
router.get("/", (_req, res) => {
    res.send("🚀 Bildare backend is running!");
});
// ----------------- GA Proxy -----------------
router.post("/analytics", async (req, res) => {
    var _a;
    try {
        const { user_id, user_name, events, page_path } = req.body;
        if (!events || !Array.isArray(events)) {
            return res.status(400).json({ success: false, error: "Events array required" });
        }
        const clientIp = ((_a = req.headers["x-forwarded-for"]) === null || _a === void 0 ? void 0 : _a.toString().split(",")[0].trim()) ||
            req.socket.remoteAddress ||
            undefined;
        const payload = {
            client_id: user_id || crypto.randomUUID(),
            user_id,
            user_properties: { user_name: { value: user_name || "Guest" } },
            ip_override: clientIp,
            events: events.map((e) => ({ name: e.name, params: { ...e.params, page_path } })),
        };
        const gaUrl = `https://www.google-analytics.com/mp/collect?measurement_id=${process.env.GA_MEASUREMENT_ID}&api_secret=${process.env.GA_API_SECRET}`;
        const gaResponse = await (0, node_fetch_1.default)(gaUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!gaResponse.ok) {
            const text = await gaResponse.text();
            console.error("GA proxy error:", text);
            return res.status(500).json({ success: false, error: text });
        }
        res.json({ success: true });
    }
    catch (err) {
        console.error("GA proxy exception:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});
// ----------------- Start Server -----------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
exports.default = router;
//# sourceMappingURL=index.js.map