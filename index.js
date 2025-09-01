import http from "http";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import bcrypt from "bcrypt";

dotenv.config();

const PORT = 3446;
const JWT_SECRET = process.env.JWT_SECRET;
let users = [];

// Helper to send JSON
const sendJSON = (res, status, obj) => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
};

const server = http.createServer(async (req, res) => {
  // ✅ CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // ✅ SIGNUP
  if (req.url === "/signup" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk.toString()));
    req.on("end", async () => {
      try {
        const { name, phone, email, password, confirm } = JSON.parse(body);
        if (!name || !phone || !email || !password || !confirm)
          return sendJSON(res, 400, { message: "All fields are required" });

        if (password !== confirm)
          return sendJSON(res, 401, { message: "Password is not the same" });

        const existingUser = users.find((u) => u.email === email);
        if (existingUser) return sendJSON(res, 409, { message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ name, phone, email, password: hashedPassword });

        sendJSON(res, 200, { message: "✅ You have successfully signed up!!!" });
      } catch (err) {
        sendJSON(res, 500, { error: err.message });
      }
    });
  }

  // ✅ SIGNIN
  else if (req.url === "/signin" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk.toString()));
    req.on("end", async () => {
      try {
        const { email, password } = JSON.parse(body);
        if (!email || !password)
          return sendJSON(res, 400, { message: "Email and password required" });

        const user = users.find((u) => u.email === email);
        if (!user) return sendJSON(res, 401, { message: "Invalid credentials" });

        const isMatched = await bcrypt.compare(password, user.password);
        if (!isMatched) return sendJSON(res, 401, { message: "Invalid credentials" });

        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "1h" });

        sendJSON(res, 200, { message: `✅ Welcome back! ${user.name}`, token });
      } catch (err) {
        sendJSON(res, 500, { error: err.message });
      }
    });
  }

  // ✅ GET USERS
  else if (req.url === "/users" && req.method === "GET") {
    sendJSON(res, 200, users);
  }

  // ✅ GOOGLE OAUTH - Step 1: Redirect to Google
  else if (req.url === "/auth/google" && req.method === "GET") {
    const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=https://registration-server-7jj9.onrender.com/auth/google/callback&response_type=code&scope=profile email`;
    res.writeHead(302, { Location: redirectUrl });
    res.end();
  }

  // ✅ GOOGLE OAUTH - Step 2: Handle callback
  else if (req.url.startsWith("/auth/google/callback") && req.method === "GET") {
    try {
      const urlParams = new URL(req.url, `http://${req.headers.host}`);
      const code = urlParams.searchParams.get("code");

      if (!code) {
        sendJSON(res, 400, { message: "No code returned from Google" });
        return;
      }

      // Exchange code for tokens
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          code,
          grant_type: "authorization_code",
          redirect_uri: `https://registration-server-7jj9.onrender.com/auth/google/callback`,
        }),
      });

      const tokens = await tokenRes.json();
      console.log("👉 Tokens:", tokens);

      // Fetch Google profile
      const profileRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      const profile = await profileRes.json();
      // console.log("👉 Google profile:", profile);


      // Save or find user
      let user = users.find((u) => u.email === profile.email);
      if (!user) {
        user = { name: profile.name, email: profile.email, googleId: profile.id };
        users.push(user);
      }

      // Sign JWT
      const appToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "1h" });

      sendJSON(res, 200, { message: `✅ Google login success, welcome ${user.name || user.email}`, token: appToken });
    } catch (err) {
      sendJSON(res, 500, { error: err.message });
    }
  }

  // ✅ NOT FOUND
  else {
    sendJSON(res, 404, { message: "Route not found" });
  }
});

server.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
