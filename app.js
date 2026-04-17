const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('雲端資料庫連線成功'))
  .catch(err => console.log('資料庫連線失敗:', err));

// 👑 設定最高管理員信箱
const ADMIN_EMAILS =['fab2ci@gmail.com', '另一個管理員@gmail.com'];

// 1. 修改 Schema：新增 password 與 salt (用於密碼加密)
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: { type: String }, // 密碼雜湊值
  salt: { type: String },     // 密碼專屬隨機鹽
  verified: { type: Boolean, default: false },
  code: String,
  codeExpires: Date,
  sessionToken: String, 
  role: { type: String, default: 'user' },
  lastLoginAt: Date, 
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// 密碼加密函式 (PBKDF2 演算法)
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

// === API 1: 登入或註冊請求 (整合密碼) ===
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: '請填寫信箱與密碼' });

    let user = await User.findOne({ email });

    if (user) {
      // 📝 帳號已存在 -> 驗證密碼
      const hashedInput = hashPassword(password, user.salt);
      if (hashedInput !== user.password) {
        return res.status(401).json({ success: false, message: '密碼錯誤' });
      }

      if (user.verified) {
        // 密碼正確且已驗證過 -> 瞬間登入，核發新通行證
        user.sessionToken = crypto.randomBytes(16).toString('hex');
        user.lastLoginAt = new Date();
        await user.save();
        return res.json({ success: true, message: '登入成功', user, token: user.sessionToken, directLogin: true });
      }
    } else {
      // 📝 帳號不存在 -> 執行註冊，加密密碼並儲存
      const salt = crypto.randomBytes(16).toString('hex');
      const hashedPassword = hashPassword(password, salt);
      const userRole = ADMIN_EMAILS.includes(email) ? 'admin' : 'user';
      
      user = new User({ email, password: hashedPassword, salt, role: userRole });
    }

    // 尚未驗證 (新註冊或之前沒點驗證碼) -> 寄送驗證信
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60000);
    user.code = code;
    user.codeExpires = expires;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: '外送記帳 APP - 帳號驗證碼',
      html: `<div style="padding:20px; font-family:sans-serif;"><h2>您的驗證碼為：<span style="color:#FF6B35; font-size:32px; letter-spacing:4px;">${code}</span></h2><p>請在 10 分鐘內於 APP 輸入此驗證碼完成驗證。</p></div>`
    });

    // 回傳 directLogin: false，告訴前端要顯示「輸入驗證碼」的畫面
    res.json({ success: true, message: '驗證碼已寄出', directLogin: false });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// === API 2: 驗證驗證碼 ===
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: '找不到帳號' });
    if (user.code !== code || new Date() > user.codeExpires) {
      return res.status(400).json({ success: false, message: '驗證碼錯誤或已過期' });
    }
    
    user.verified = true;
    user.code = null; 
    user.sessionToken = crypto.randomBytes(16).toString('hex');
    user.lastLoginAt = new Date();
    await user.save();
    
    res.json({ success: true, message: '登入成功', user, token: user.sessionToken });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// === API 3: 檢查帳號存活與共用踢下線 ===
app.post('/api/auth/check', async (req, res) => {
  const { email, token } = req.body;
  const user = await User.findOne({ email });
  if (!user || !user.verified) return res.json({ active: false, reason: 'deleted' });
  if (user.sessionToken !== token) return res.json({ active: false, reason: 'kicked', kickedAt: user.lastLoginAt });
  res.json({ active: true });
});

// === API 4: 管理員取得清單 ===
app.post('/api/admin/users', async (req, res) => {
  try {
    const { adminEmail, token } = req.body;
    const admin = await User.findOne({ email: adminEmail, sessionToken: token, role: 'admin' });
    if (!admin) return res.status(403).json({ success: false, message: '權限不足或通行證失效' });

    const users = await User.find().sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// === API 5: 管理員刪除帳號 ===
app.post('/api/admin/delete', async (req, res) => {
  try {
    const { adminEmail, token, targetEmail } = req.body;
    const admin = await User.findOne({ email: adminEmail, sessionToken: token, role: 'admin' });
    if (!admin) return res.status(403).json({ success: false, message: '權限不足' });

    await User.deleteOne({ email: targetEmail });
    res.json({ success: true, message: '帳號已永久刪除' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`伺服器運行中，PORT: ${PORT}`));
