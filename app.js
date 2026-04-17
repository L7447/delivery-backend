// app.js
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors'); // 必須安裝 cors: npm install cors
require('dotenv').config(); // 讀取環境變數

const app = express();
app.use(express.json());
app.use(cors()); // 允許前端跨域請求

// 改成讀取 process.env.MONGO_URI
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('雲端資料庫連線成功'))
  .catch(err => console.log('資料庫連線失敗:', err));

// 使用者 Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  verified: { type: Boolean, default: false },
  code: String,
  codeExpires: Date,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// 郵件寄送設定 (請替換為您的信箱與應用程式密碼)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// API 1: 發送 6 位數驗證碼
app.post('/api/auth/send', async (req, res) => {
  try {
    const { email } = req.body;
    const code = Math.floor(100000 + Math.random() * 900000).toString(); // 產生 6 位數
    const expires = new Date(Date.now() + 10 * 60000); // 10分鐘有效

    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, code, codeExpires: expires });
    } else {
      user.code = code;
      user.codeExpires = expires;
    }
    await user.save();

    await transporter.sendMail({
      from: '您的寄件信箱@gmail.com',
      to: email,
      subject: '外送記帳 APP - 登入驗證碼',
      html: `<div style="padding:20px; font-family:sans-serif;">
               <h2>您的登入驗證碼為：<span style="color:#FF6B35; font-size:32px; letter-spacing:4px;">${code}</span></h2>
               <p>請在 10 分鐘內於 APP 輸入此驗證碼完成登入。</p>
             </div>`
    });

    res.json({ success: true, message: '驗證碼已寄出' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// API 2: 驗證驗證碼
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: '找不到帳號' });
    
    if (user.code !== code || new Date() > user.codeExpires) {
      return res.status(400).json({ success: false, message: '驗證碼錯誤或已過期' });
    }
    
    user.verified = true;
    user.code = null; // 驗證後清空
    await user.save();
    
    res.json({ success: true, message: '登入成功', user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// API 3: 管理員取得所有註冊用戶清單
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// API 4: 管理員刪除/封鎖帳號
app.delete('/api/admin/users/:email', async (req, res) => {
  try {
    await User.deleteOne({ email: req.params.email });
    res.json({ success: true, message: '帳號已永久刪除' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// API 5: 檢查帳號是否存活 (前端每次操作前可驗證)
app.post('/api/auth/check', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && user.verified) res.json({ active: true });
  else res.json({ active: false });
});

// 雲端伺服器會自動分配 PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`伺服器運行中，PORT: ${PORT}`));