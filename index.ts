// src/index.ts
import express, { Request, Response, NextFunction, Router } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GithubStrategy } from "passport-github2";
import { VerifyCallback } from "passport-oauth2";
import { Profile } from "passport-google-oauth20";
import fetch from "node-fetch";

const app = express();
const prisma = new PrismaClient();
const router = Router();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

type PassportDone = (error: Error | null, user?: any) => void;

interface GoogleProfile {
  id: string;
  displayName: string;
  emails?: { value: string }[];
  photos?: { value: string }[];
  provider: string;
  // add any other fields you need
}

interface GitHubProfile {
  id: string;
  username: string;
  displayName?: string;
  emails?: { value: string }[];
  photos?: { value: string }[];
  provider: string;
  // add more fields if needed
}

// ----------------- CORS -----------------

const allowedOrigins = ["http://localhost:3000", "https://bildare.vercel.app"];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true); // allow non-browser requests
      if (allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Handle OPTIONS preflight requests
app.options("*", cors({ origin: allowedOrigins, credentials: true }));
// ----------------- Session -----------------
const isProduction = process.env.NODE_ENV === "production";
app.set("trust proxy", 1);
app.use(
  session({
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
  })
);

// ----------------- Passport -----------------
app.use(passport.initialize());

// ----------------- Email Transporter -----------------
const transporter = nodemailer.createTransport({
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

const generateAccessToken = (userId: number) =>
  jwt.sign({ userId }, SECRET_KEY, { expiresIn: "1h" });

const generateRefreshToken = (userId: number) =>
  jwt.sign({ userId }, REFRESH_SECRET_KEY, { expiresIn: "7d" });

// ----------------- OTP Email Helper -----------------
const sendOtpEmail = async (email: string, otp: string) => {
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
  } catch (err) {
    console.error("❌ Failed to send OTP email:", err);
  }
};

// ----------------- Logging -----------------
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`Incoming request: ${req.method} ${req.url}`);
  next();
});

// ----------------- Google OAuth (Prisma) -----------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackURL: isProduction
        ? "https://bildare-backend.onrender.com/auth/google/callback"
        : "http://localhost:5000/auth/google/callback",
    },
    async (
      accessToken: string,
      refreshToken: string,
      profile: GoogleProfile,
      done: PassportDone
    ) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error("Email not provided by Google"));

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
        const hashedRefresh = await bcrypt.hash(refresh, 10);

        // Store hashed refresh token in Prisma
        user = await prisma.user.update({
          where: { user_id: user.user_id },
          data: { refresh_token: hashedRefresh },
        });

        done(null, { ...user, accessToken: access, refreshToken: refresh });
      } catch (err) {
        done(err as Error);
      }
    }
  )
);

// ----------------- Passport GitHub Strategy -----------------
passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID || "",
      clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
      callbackURL: isProduction
        ? "https://bildare-backend.onrender.com/auth/github/callback"
        : "http://localhost:5000/auth/github/callback",
      scope: ["user:email"],
    },
    async (
      accessToken: string,
      refreshToken: string,
      profile: GitHubProfile,
      done: PassportDone
    ) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error("GitHub email not available"));

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
        const hashedRefresh = await bcrypt.hash(refresh, 10);

        // Store hashed refresh token in Prisma
        user = await prisma.user.update({
          where: { user_id: user.user_id },
          data: { refresh_token: hashedRefresh },
        });

        done(null, { ...user, accessToken: access, refreshToken: refresh });
      } catch (err) {
        done(err as Error);
      }
    }
  )
);

// -----------------  Routes -----------------
router.post("/signup", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser)
      return res.status(400).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- 🔁 Resend OTP -----------------
router.post("/resend-otp", async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "User not found" });
    if (user.is_verified) return res.status(400).json({ error: "Already verified" });

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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- 2️⃣ Verify OTP -----------------
router.post("/verify-otp", async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp)
      return res.status(400).json({ error: "Email and OTP are required" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "User not found" });
    if (user.is_verified) return res.status(400).json({ error: "Already verified" });

    // If OTP expired or invalid (if you stored OTP)
if (!user.otp || !user.otp_expires || new Date() > user.otp_expires) {
  return res.status(400).json({ error: "OTP has expired. Please request a new one." });
}

if (user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });


    await prisma.user.update({
      where: { email },
      data: {
        is_verified: true,
        // otp: null,
        // otpExpires: null,
      },
    });

    res.json({ message: "OTP verified. Now complete your profile." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- 3️⃣ Complete Profile -----------------
router.post("/complete-profile", async (req: Request, res: Response) => {
  try {
    const { email, username, role, region, interests } = req.body;

    if (!email || !username || !role || !region) {
      return res.status(400).json({ error: "Email, username, role, and region are required" });
    }

    // Fetch user
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.is_verified) return res.status(400).json({ error: "Email not verified" });

    // Generate JWTs
    const accessToken = generateAccessToken(user.user_id);
    const refreshToken = generateRefreshToken(user.user_id);

    // Hash refresh token before storing
    const hashedRefresh = await bcrypt.hash(refreshToken, 10);

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
      role: user.role ?? undefined,
      region: user.region ?? undefined,
      interests: user.interests,
      accessToken,
      refreshToken,
    };

    return res.json({
      message: "Profile completed successfully!",
      user: req.session.user,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});


// ----------------- 4️⃣ Login -----------------
router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.is_verified) return res.status(400).json({ error: "Email not verified" });

    // Check password
    const valid = await bcrypt.compare(password, user.password_hash || "");
    if (!valid) return res.status(400).json({ error: "Invalid password" });

    // Generate JWTs
    const accessToken = generateAccessToken(user.user_id);
    const refreshToken = generateRefreshToken(user.user_id);

    // Hash refresh token before storing
    const hashedRefresh = await bcrypt.hash(refreshToken, 10);

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
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ----------------- /me -----------------
router.get("/me", (req: Request, res: Response) => {
  const sessionUser = req.session.user;
  if (!sessionUser) return res.status(401).json({ error: "Not authenticated" });

  const { id, email, username, interests, accessToken, refreshToken } = sessionUser;
  res.json({ id, email, username, interests, accessToken, refreshToken });
});

// ----------------- Logout -----------------
router.post("/logout", (req: Request, res: Response) => {
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
router.get("/profile", async (req: Request, res: Response) => {
  try {
    if (!req.session.user) return res.status(401).json({ error: "Not authenticated" });

    const user = await prisma.user.findUnique({ where: { user_id: req.session.user.id } });
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ message: `Welcome ${user.email}`, region: user.region, interests: user.interests });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- Refresh Access Token -----------------
router.post("/token", async (req: Request, res: Response) => {
  try {
    const sessionToken = req.session.user?.refreshToken;
    const bodyToken = req.body.refreshToken;
    const refreshToken = sessionToken || bodyToken;
    if (!refreshToken) return res.status(401).json({ error: "Refresh token required" });

    const user = await prisma.user.findFirst({
      where: { refresh_token: refreshToken },
    });
    if (!user) return res.status(403).json({ error: "Invalid refresh token" });

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || "secret", (err:any) => {
      if (err) return res.status(403).json({ error: "Invalid refresh token" });

      const accessToken = generateAccessToken(user.user_id);
      if (req.session.user) req.session.user.accessToken = accessToken;

      res.json({ accessToken });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- Request Password Reset -----------------
router.post("/request-password-reset", async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });

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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- Verify Reset Token -----------------
router.post("/verify-reset-token", async (req: Request, res: Response) => {
  try {
    const { email, token } = req.body;
    if (!email || !token) return res.status(400).json({ error: "Email and token are required" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.reset_password_token !== token || !user.reset_password_expires || new Date() > user.reset_password_expires) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    res.json({ message: "Token is valid. You can now reset your password." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- Reset Password -----------------
router.post("/reset-password", async (req: Request, res: Response) => {
  try {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword) return res.status(400).json({ error: "All fields are required" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.reset_password_token !== token || !user.reset_password_expires || new Date() > user.reset_password_expires) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { email },
      data: {
        password_hash: hashedPassword,
        reset_password_token: null,
        reset_password_expires: null,
      },
    });

    res.json({ message: "Password reset successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- Fetch All Users -----------------
router.get("/users", async (_req: Request, res: Response) => {
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------------- Delete User -----------------
router.delete("/users", async (req: Request, res: Response) => {
  try {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "User ID is required" });

    const deleted = await prisma.user.delete({ where: { user_id: id } });
    res.json({ message: "User deleted successfully", id: deleted.user_id });
  } catch (err) {
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
router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth", session: false }),
  async (req: Request, res: Response) => {
    try {
      const userData = req.user as {
        id: number;
        email: string;
        username?: string;
        role?: string;
        accessToken: string;
        refreshToken: string;
      };

      // Upsert user in DB
      const user = await prisma.user.upsert({
        where: { email: userData.email },
        update: {
          username: userData.username || userData.email.split("@")[0],
          refresh_token: await bcrypt.hash(userData.refreshToken, 10),
        },
        create: {
          email: userData.email,
          username: userData.username || userData.email.split("@")[0],
          is_verified: true,
          region: "Unknown",
          interests: [],
          refresh_token: await bcrypt.hash(userData.refreshToken, 10),
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
    } catch (err) {
      console.error(err);
      res.status(500).send("OAuth login failed");
    }
  }
);

// ----------------- GitHub OAuth -----------------
router.get("/auth/github", passport.authenticate("github"));

router.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/auth", session: false }),
  async (req: Request, res: Response) => {
    try {
      const userData = req.user as {
        id: number;
        email: string;
        username?: string;
        role?: string;
        accessToken: string;
        refreshToken: string;
      };

      // Upsert user in DB
      const user = await prisma.user.upsert({
        where: { email: userData.email },
        update: {
          username: userData.username || userData.email.split("@")[0],
          refresh_token: await bcrypt.hash(userData.refreshToken, 10),
        },
        create: {
          email: userData.email,
          username: userData.username || userData.email.split("@")[0],
          is_verified: true,
          region: "Unknown",
          interests: [],
          refresh_token: await bcrypt.hash(userData.refreshToken, 10),
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
    } catch (err) {
      console.error(err);
      res.status(500).send("OAuth login failed");
    }
  }
);

// ----------------- Contact form -----------------
router.post("/contact", async (req: Request, res: Response) => {
  try {
    const { name, email, subject, message } = req.body as {
      name?: string;
      email?: string;
      subject?: string;
      message?: string;
    };

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
  } catch (err) {
    console.error("Error sending contact email:", err);
    res.status(500).json({ error: "Failed to send message." });
  }
});

// ----------------- Root -----------------
router.get("/", (_req: Request, res: Response) => {
  res.send("🚀 Bildare backend is running!");
});

// ----------------- GA Proxy -----------------
router.post("/analytics", async (req: Request, res: Response) => {
  try {
    const { user_id, user_name, events, page_path } = req.body as {
      user_id?: string;
      user_name?: string;
      events?: { name: string; params?: Record<string, any> }[];
      page_path?: string;
    };

    if (!events || !Array.isArray(events)) {
      return res.status(400).json({ success: false, error: "Events array required" });
    }

    const clientIp =
      req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
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

    const gaResponse = await fetch(gaUrl, {
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
  } catch (err: any) {
    console.error("GA proxy exception:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ----------------- Start Server -----------------
// All your routes
app.use("/", router);
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));


export default router;