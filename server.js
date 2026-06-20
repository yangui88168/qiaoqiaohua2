require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const session = require("express-session");
const multer = require("multer");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const cors = require("cors");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg"); 
const { v4: uuidv4 } = require("uuid"); 

// ========== 环境变量检查 ==========
if (!process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET 未配置");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL 未配置");
  process.exit(1);
}

const app = express();
const server = http.createServer(app);

// ========== PostgreSQL 连接池 ==========
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false 
  }
});

pool.on("error", (err) => {
  console.error("Unexpected error on idle client", err); 
  process.exit(-1);
});

// ========== Render 反向代理信任 ==========
app.set("trust proxy", 1);

// ========== CORS 安全配置 ==========
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGIN
  ? process.env.ALLOWED_ORIGIN.split(",").map(o => o.trim())
  : true; 

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({
  origin: ALLOWED_ORIGINS,
  credentials: true
}));
app.use(express.json({ limit: "1mb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "登录尝试过多，请15分钟后再试" }
});
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "搜索太频繁，请稍后再试" }
});
const friendRequestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "请求太频繁，请稍后再试" }
});

// ========== 目录与持久化配置 ==========
const DATA_DIR = process.env.DATA_DIR || __dirname;        
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// 统一文件上传路径
app.use("/uploads", express.static(UPLOAD_DIR, {
  maxAge: "7d"
}));

// ========== Session ==========
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  ccookie: {
  httpOnly: true,
  secure: true,
  sameSite: "none",
  maxAge: 7 * 24 * 60 * 60 * 1000
}
});
app.use(sessionMiddleware);

// ========== 文件上传配置 ==========
const ALLOWED_FILE_TYPES = {
  "jpg": { ext: ".jpg", mime: "image/jpeg", maxSize: 5 * 1024 * 1024 },
  "jpeg": { ext: ".jpeg", mime: "image/jpeg", maxSize: 5 * 1024 * 1024 },
  "png": { ext: ".png", mime: "image/png", maxSize: 5 * 1024 * 1024 },
  "gif": { ext: ".gif", mime: "image/gif", maxSize: 5 * 1024 * 1024 },
  "webp": { ext: ".webp", mime: "image/webp", maxSize: 5 * 1024 * 1024 },
  "mp3": { ext: ".mp3", mime: "audio/mpeg", maxSize: 15 * 1024 * 1024 },
  "wav": { ext: ".wav", mime: "audio/wav", maxSize: 15 * 1024 * 1024 },
  "ogg": { ext: ".ogg", mime: "audio/ogg", maxSize: 15 * 1024 * 1024 },
  "mp4": { ext: ".mp4", mime: "video/mp4", maxSize: 30 * 1024 * 1024 },
  "webm": { ext: ".webm", mime: "video/webm", maxSize: 30 * 1024 * 1024 },
  "pdf": { ext: ".pdf", mime: "application/pdf", maxSize: 20 * 1024 * 1024 },
  "zip": { ext: ".zip", mime: "application/zip", maxSize: 20 * 1024 * 1024 },
  "txt": { ext: ".txt", mime: "text/plain", maxSize: 5 * 1024 * 1024 }
};

function getFileTypeInfo(filename) {
  const ext = path.extname(filename).toLowerCase().substring(1);
  return ALLOWED_FILE_TYPES[ext] || null;
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const info = getFileTypeInfo(file.originalname);
    if (!info) return cb(new Error("不支持的文件类型"));
    const name = crypto.randomBytes(8).toString("hex") + info.ext;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 30 * 1024 * 1024 }, 
  fileFilter: (req, file, cb) => {
    const info = getFileTypeInfo(file.originalname);
    if (!info) return cb(new Error("不支持的文件类型"));
    cb(null, true);
  }
});

app.use(express.static("public"));

const onlineUsers = new Map();

// ========== ❗ 修改 1: 保证 avatar 永远统一格式输出 (关键补丁) ==========
const AVATAR_SQL = `CASE 
  WHEN avatar IS NULL OR avatar = '' THEN '/default-avatar.png'
  WHEN avatar LIKE 'http%' THEN avatar
  WHEN avatar LIKE '/api/file/%' THEN avatar
  WHEN avatar LIKE '/uploads/%' THEN avatar
  ELSE CONCAT('/uploads/', avatar)
END AS avatar`;

// ========== 工具 ==========
function genInvite() {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

function sanitizeText(input) {
  if (typeof input !== "string") return "";
  return input.replace(/<[^>]*>/g, "").replace(/[<>\"\"]/g, "").substring(0, 500);
}

async function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "未登录" });
  }
  try {
    const result = await pool.query(`SELECT id, username, password, nickname, ${AVATAR_SQL}, chat_background, gender, region, signature, invite_code FROM users WHERE id = $1`, [req.session.userId]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "用户不存在或未登录" });
    }
    req.user = result.rows[0];
    next();
  } catch (e) {
    console.error("Auth error:", e);
    res.status(500).json({ error: "认证失败" });
  }
}

// ========== Socket.IO 配置 ==========
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    credentials: true
  }
});

io.engine.use(sessionMiddleware);

io.use(async (socket, next) => {
  const session = socket.request.session;
  if (session && session.userId) {
    try {
      const result = await pool.query(`SELECT id, username, nickname, ${AVATAR_SQL} FROM users WHERE id = $1`, [session.userId]);
      if (result.rows.length > 0) {
        socket.userId = session.userId;
        socket.msgTimestamps = [];
        next();
      } else {
        next(new Error("认证失败: 用户不存在"));
      }
    } catch (e) {
      console.error("Socket auth error:", e);
      next(new Error("认证失败"));
    }
  } else {
    next(new Error("认证失败: 无会话或用户ID"));
  }
});

io.on("connection", (socket) => {
  if (socket.userId) {
    onlineUsers.set(socket.userId, socket.id);
    socket.join(`user_${socket.userId}`);
    pool.query("SELECT username FROM users WHERE id = $1", [socket.userId])
      .then(res => console.log(`用户 ${res.rows[0]?.username || socket.userId} 已连接`))
      .catch(e => console.error("Error fetching username for connection log:", e));
  }

  socket.on("private message", async (data, ack) => {
    if (!socket.userId) {
      if (typeof ack === "function") ack({ success: false, error: "未登录" });
      return;
    }
    const now = Date.now();
    socket.msgTimestamps = socket.msgTimestamps.filter(t => now - t < 1000);
    if (socket.msgTimestamps.length >= 5) {
      if (typeof ack === "function") ack({ success: false, error: "发送过快" });
      return;
    }
    socket.msgTimestamps.push(now);

    const { to, toType, type = "text", content, fileName, duration, clientMsgId } = data;
    if (!to || !toType) {
      if (typeof ack === "function") ack({ success: false, error: "数据不完整" });
      return;
    }
    if (typeof content !== "string" || content.trim().length === 0) {
      if (typeof ack === "function") ack({ success: false, error: "内容不能为空" });
      return;
    }

    try {
      let messageId;
      if (toType === "friend") {
        const friendCheck = await pool.query(
          "SELECT 1 FROM user_friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)",
          [socket.userId, to]
        );
        if (friendCheck.rows.length === 0) {
          if (typeof ack === "function") ack({ success: false, error: "不是好友" });
          return;
        }
        const insertMsg = await pool.query(
          "INSERT INTO messages (from_user_id, to_id, to_type, type, content, file_name, duration, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
          [socket.userId, to, toType, type, content.trim(), fileName, duration, now]
        );
        messageId = insertMsg.rows[0].id;

        const message = { id: messageId, from: socket.userId, to: to, toType, type, content: content.trim(), fileName, duration, timestamp: now };
        io.to(`user_${socket.userId}`).emit("chat message", message);
        io.to(`user_${to}`).emit("chat message", message);
        if (typeof ack === "function") ack({ success: true, msg: message });
      } else if (toType === "group") {
        const groupCheck = await pool.query(
          "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2",
          [to, socket.userId]
        );
        if (groupCheck.rows.length === 0) {
          if (typeof ack === "function") ack({ success: false, error: "不在群组中" });
          return;
        }
        const insertMsg = await pool.query(
          "INSERT INTO messages (from_user_id, to_id, to_type, type, content, file_name, duration, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
          [socket.userId, to, toType, type, content.trim(), fileName, duration, now]
        );
        messageId = insertMsg.rows[0].id;

        const message = { id: messageId, from: socket.userId, to: to, toType, type, content: content.trim(), fileName, duration, timestamp: now };
        const groupMembers = await pool.query("SELECT user_id FROM group_members WHERE group_id = $1", [to]);
        groupMembers.rows.forEach(member => {
          io.to(`user_${member.user_id}`).emit("chat message", message);
        });
        if (typeof ack === "function") ack({ success: true, msg: message });
      }
    } catch (e) {
      console.error("Error sending message:", e);
      if (typeof ack === "function") ack({ success: false, error: "发送失败" });
    }
  });

  socket.on("call_offer", async (data) => {
    const { to, offer, isVideo } = data; 
    if (!to || !offer) return;
    try {
      const friendCheck = await pool.query(
        "SELECT 1 FROM user_friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)",
        [socket.userId, to]
      );
      if (friendCheck.rows.length === 0) return; 
      io.to(`user_${to}`).emit("call_offer", { from: socket.userId, offer, isVideo }); 
    } catch (e) {
      console.error("Error checking friend status for call_offer:", e);
    }
  });
  socket.on("call_answer", (data) => {
    const { to, answer } = data;
    if (!to || !answer) return;
    io.to(`user_${to}`).emit("call_answer", { from: socket.userId, answer });
  });
  socket.on("call_candidate", (data) => {
    const { to, candidate } = data;
    if (!to || !candidate) return;
    io.to(`user_${to}`).emit("call_candidate", { from: socket.userId, candidate });
  });
  socket.on("call_reject", (data) => {
    const { to } = data;
    if (!to) return;
    io.to(`user_${to}`).emit("call_rejected", { from: socket.userId });
  });
  socket.on("call_end", (data) => {
    const { to } = data;
    if (!to) return;
    io.to(`user_${to}`).emit("call_ended", { from: socket.userId });
  });

  socket.on("disconnect", () => {
    if (socket.userId) onlineUsers.delete(socket.userId);
  });

  socket.on("mark_messages_read", async (data) => {
    const { friendId } = data;
    if (!friendId) return;
    try {
      await pool.query(
        "UPDATE messages SET read_at = $1 WHERE from_user_id = $2 AND to_id = $3 AND to_type = 'friend' AND read_at IS NULL",
        [Date.now(), friendId, socket.userId]
      );
      io.to(`user_${friendId}`).emit("message_read", { fromId: socket.userId });
    } catch (e) {
      console.error("Error marking messages as read:", e);
    }
  });
});

// ❗ 修改 2: 统一 socket user payload (3秒广播)
setInterval(() => {
  const onlineList = Array.from(onlineUsers.keys());
  io.emit("online_users", { users: onlineList });
}, 3000);

// ========== 受保护的文件下载 ==========
app.get("/api/file/:name", auth, async (req, res) => {
  const filename = path.basename(req.params.name);
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "文件不存在" });
  res.sendFile(filePath);
});

// ========== API 路由 ==========
app.post("/api/register", async (req, res) => {
  const { username, password, nickname, inviteCode } = req.body;
  if (!username || !password || !inviteCode) return res.json({ error: "必填项缺失" });
  const validInviteCodes = [
  process.env.INVITE_CODE,
  "MANUS",
  "20040705"
];

if (!validInviteCodes.includes(inviteCode)) {
  return res.json({ error: "无效邀请码" });
}

  try {
    const userCheck = await pool.query("SELECT 1 FROM users WHERE username = $1", [username]);
    if (userCheck.rows.length > 0) return res.json({ error: "用户名已存在" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (username, password, nickname, invite_code, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, nickname, invite_code",
      [username, hashedPassword, nickname || username, genInvite(), Date.now()]
    );
req.session.userId = result.rows[0].id;

req.session.userId = result.rows[0].id;

req.session.save((err) => {
  if (err) {
    console.error("Session save error:", err);
    return res.status(500).json({
      error: "Session保存失败"
    });
  }

  return res.json({
    success: true,
    user: result.rows[0]
  });
});

} catch (e) {
  console.error("注册错误:", e);

  return res.status(500).json({
    error: "注册失败",
    detail: e.message
  });
}
app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(`SELECT id, password, username, nickname, ${AVATAR_SQL} FROM users WHERE username = $1`, [username]);
    if (result.rows.length === 0) return res.json({ error: "用户不存在" });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ error: "密码错误" });
    req.session.userId = user.id;

req.session.save((err) => {
  if (err) {
    console.error("Session save error:", err);
    return res.status(500).json({
      error: "Session保存失败"
    });
  }

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      nickname: user.nickname,
      avatar: user.avatar
    }
  });
});
  } catch (e) {
    res.json({ error: "登录失败" });
  }
});

app.post("/api/change-password", auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.json({ error: "旧密码和新密码不能为空" });
  if (newPassword.length < 8) return res.json({ error: "新密码至少8位" });
  try {
    const isMatch = await bcrypt.compare(oldPassword, req.user.password);
    if (!isMatch) return res.json({ error: "旧密码不正确" });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, req.user.id]);
    res.json({ success: true });
  } catch (e) {
    res.json({ error: "修改失败" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, username, nickname, ${AVATAR_SQL}, chat_background, gender, region, signature, invite_code, created_at FROM users WHERE id = $1`, [req.user.id]);
    const u = result.rows[0];
    res.json({
      success: true,
      user: {
        id: u.id, username: u.username, nickname: u.nickname, avatar: u.avatar,
        chatBackground: u.chat_background, gender: u.gender, region: u.region,
        signature: u.signature, inviteCode: u.invite_code
      }
    });
  } catch (e) {
    res.status(500).json({ error: "获取失败" });
  }
});

app.get("/api/friends", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.nickname, ${AVATAR_SQL.replace(/avatar/g, 'u.avatar')} FROM users u JOIN user_friends f ON u.id = f.friend_id WHERE f.user_id = $1`,
      [req.user.id]
    );
    res.json({ friends: result.rows });
  } catch (e) {
    res.json({ error: "获取失败" });
  }
});

app.get("/api/search", auth, searchLimiter, async (req, res) => {
  const q = req.query.q?.toLowerCase() || "";
  try {
    const result = await pool.query(
      `SELECT id, username, nickname, ${AVATAR_SQL} FROM users WHERE id != $1 AND (username ILIKE $2 OR nickname ILIKE $2) LIMIT 10`,
      [req.user.id, `%${q}%`]
    );
    res.json({ users: result.rows });
  } catch (e) {
    res.json({ error: "搜索失败" });
  }
});

app.post("/api/friend-request", auth, friendRequestLimiter, async (req, res) => {
  const { to, toUsername, message } = req.body;
  let targetId = to;
  if (!targetId && toUsername) {
    const user = await pool.query("SELECT id FROM users WHERE username = $1", [toUsername]);
    if (user.rows.length === 0) return res.json({ error: "用户不存在" });
    targetId = user.rows[0].id;
  }
  if (!targetId || targetId === req.user.id) return res.json({ error: "无效请求" });

  try {
    const exist = await pool.query("SELECT 1 FROM user_friends WHERE user_id = $1 AND friend_id = $2", [req.user.id, targetId]);
    if (exist.rows.length > 0) return res.json({ error: "已是好友" });
    await pool.query(
      "INSERT INTO friend_requests (from_user_id, to_user_id, message, status, timestamp) VALUES ($1, $2, $3, 'pending', $4) ON CONFLICT DO NOTHING",
      [req.user.id, targetId, sanitizeText(message || "请求添加好友"), Date.now()]
    );
    io.to(`user_${targetId}`).emit("new_friend_request");
    res.json({ success: true, message: "申请已发送" });
  } catch (e) {
    res.json({ error: "发送失败" });
  }
});

app.get("/api/friend-requests", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT fr.id, fr.from_user_id as from, fr.to_user_id as to, fr.message, fr.status, fr.timestamp, u_from.username as from_username, u_to.username as to_username FROM friend_requests fr JOIN users u_from ON fr.from_user_id = u_from.id JOIN users u_to ON fr.to_user_id = u_to.id WHERE fr.to_user_id = $1 OR fr.from_user_id = $1 ORDER BY fr.timestamp DESC`,
      [req.user.id]
    );
    res.json({ requests: result.rows });
  } catch (e) {
    res.json({ error: "获取失败" });
  }
});

app.post("/api/friend-request/:id/accept", auth, async (req, res) => {
  try {
    const request = await pool.query("SELECT * FROM friend_requests WHERE id = $1 AND to_user_id = $2 AND status = 'pending'", [req.params.id, req.user.id]);
    if (request.rows.length === 0) return res.json({ error: "请求不存在" });
    const fromId = request.rows[0].from_user_id;
    await pool.query("BEGIN");
    await pool.query("UPDATE friend_requests SET status = 'accepted' WHERE id = $1", [req.params.id]);
    await pool.query("INSERT INTO user_friends (user_id, friend_id) VALUES ($1, $2), ($2, $1) ON CONFLICT DO NOTHING", [req.user.id, fromId]);
    await pool.query("COMMIT");
    io.to(`user_${fromId}`).emit("friend_accepted", { friendId: req.user.id });
    res.json({ success: true });
  } catch (e) {
    await pool.query("ROLLBACK");
    res.json({ error: "操作失败" });
  }
});

app.post("/api/friend-request/:id/reject", auth, async (req, res) => {
  try {
    await pool.query("UPDATE friend_requests SET status = 'rejected' WHERE id = $1 AND to_user_id = $2", [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (e) {
    res.json({ error: "拒绝失败" });
  }
});

app.post("/api/friend-remove", auth, async (req, res) => {
  const { friendId } = req.body;
  try {
    await pool.query("DELETE FROM user_friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)", [req.user.id, friendId]);
    io.to(`user_${friendId}`).emit("friend_removed", { friendId: req.user.id });
    res.json({ success: true });
  } catch (e) {
    res.json({ error: "删除失败" });
  }
});

app.post("/api/groups", auth, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.json({ error: "名称不能为空" });
  try {
    await pool.query("BEGIN");
    const newGroup = await pool.query("INSERT INTO groups (name, owner_id) VALUES ($1, $2) RETURNING id, name", [sanitizeText(name), req.user.id]);
    const groupId = newGroup.rows[0].id;
    await pool.query("INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'owner')", [groupId, req.user.id]);
    await pool.query("COMMIT");
    res.json({ group: newGroup.rows[0] });
  } catch (e) {
    await pool.query("ROLLBACK");
    res.json({ error: "创建失败" });
  }
});

app.get("/api/groups", auth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = $1`, [req.user.id]);
    res.json({ groups: result.rows });
  } catch (e) {
    res.json({ error: "获取失败" });
  }
});

app.get("/api/messages/friend/:friendId", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, from_user_id as from, to_id as to, to_type as toType, type, content, file_name as fileName, duration, timestamp, read_at FROM messages WHERE ((from_user_id = $1 AND to_id = $2) OR (from_user_id = $2 AND to_id = $1)) AND to_type = 'friend' ORDER BY timestamp ASC",
      [req.user.id, req.params.friendId]
    );
    res.json({ messages: result.rows });
  } catch (e) {
    res.json({ error: "获取失败" });
  }
});

app.get("/api/messages/group/:groupId", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, from_user_id as from, to_id as to, to_type as toType, type, content, file_name as fileName, duration, timestamp FROM messages WHERE to_id = $1 AND to_type = 'group' ORDER BY timestamp ASC",
      [req.params.groupId]
    );
    res.json({ messages: result.rows });
  } catch (e) {
    res.json({ error: "获取失败" });
  }
});

app.post("/api/avatar/upload", auth, upload.single("avatar"), async (req, res) => {
  if (!req.file) return res.json({ error: "未选择文件" });
  try {
    const avatarPath = req.file.filename;
    await pool.query("UPDATE users SET avatar = $1 WHERE id = $2", [avatarPath, req.user.id]);
    await pool.query("INSERT INTO uploaded_files (user_id, filename, original_name, type) VALUES ($1, $2, $3, 'avatar')", [req.user.id, avatarPath, req.file.originalname]);
    res.json({ success: true, avatar: `/uploads/${avatarPath}` });
  } catch (e) {
    res.json({ error: "上传失败" });
  }
});

app.post("/api/background/upload", auth, upload.single("background"), async (req, res) => {
  if (!req.file) return res.json({ error: "未选择文件" });
  try {
    const bgPath = req.file.filename;
    await pool.query("UPDATE users SET chat_background = $1 WHERE id = $2", [bgPath, req.user.id]);
    res.json({ success: true, url: `/uploads/${bgPath}` });
  } catch (e) {
    res.json({ error: "上传失败" });
  }
});

app.post("/api/upload", auth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.json({ error: "上传失败" });
  try {
    const filename = req.file.filename;
    await pool.query("INSERT INTO uploaded_files (user_id, filename, original_name, type) VALUES ($1, $2, $3, 'general')", [req.user.id, filename, req.file.originalname]);
    res.json({ success: true, url: `/api/file/${filename}`, filename });
  } catch (e) {
    res.json({ error: "存储失败" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

server.listen(process.env.PORT || 3000, () => {
  console.log("Server running on port " + (process.env.PORT || 3000));
});
