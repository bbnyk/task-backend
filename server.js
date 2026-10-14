require('dotenv').config();

const express = require('express');
const app = express();

const cors = require('cors');

// ติดป้ายประกาศ: อนุญาตให้ทุกโดเมนสามารถเข้ามาดึงข้อมูลได้!
app.use(cors());

// เปิดใช้งานการรับข้อมูลแบบ JSON
app.use(express.json());

const PORT = process.env.PORT || 3000;

// 1. นำไฟล์ db.js มารันเพื่อเชื่อมต่อ Database
require('./db');

// 2. นำพิมพ์เขียว (Model) ที่เราสร้างไว้เข้ามาใช้งาน
const Task = require('./models/Task');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const SECRET_KEY = process.env.JWT_SECRET;

// API สมัครสมาชิก (เข้ารหัสรหัสผ่าน)
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // นำเอาพาสเวิร์ดไป (Hash) 10 รอบ
        const hashedPassword = await bcrypt.hash(password, 10);

        // สร้าง User ใหม่ โดยใช้รหัสที่มีการเข้ารหัสแล้ว
        const newUser = new User({
            username: username,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ message: "สมัครสมาชิกสำเร็จ!" });
    } catch (err) {
        res.status(400).json({ message: "สมัครไม่สำเร็จ (Username อาจจะซ้ำ)", error: err.message });
    }
});

// API ล็อกอิน แจก Token
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 1. ค้นหาว่ามี Username นี้ในระบบไหม
        const user = await User.findOne({ username: username });
        if (!user) return res.status(404).json({ message: "ไม่พบชื่อผู้ใช้นี้" });

        // 2. เอารหัสผ่านที่พิมพ์มาไปเปรียบเทียบกับรหัสที่เข้ารหัสแล้วในฐานข้อมูล
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ message: "รหัสผ่านไม่ถูกต้อง!" });

        // 3. หากรหัสถูกต้อง ให้ JWT ที่มีอายุ 1 ชั่วโมง
        const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' });

        res.json({ message: "ล็อกอินสำเร็จ!", token: token });
    } catch (err) {
        res.status(500).json({ message: "ระบบขัดข้อง" });
    }
});

// Middleware ฟังก์ชันสำหรับตรวจ Token
const verifyToken = (req, res, next) => {
    // 1. ขอดู Token จาก Headers ที่ผู้ใช้ส่งมา
    const authHeader = req.headers['authorization'];

    // รูปแบบที่ส่งมาจะเป็น "Bearer <token>" เราต้องตัดคำว่า Bearer ออกเอาแค่ตัว Token
    const token = authHeader && authHeader.split(' ')[1];

    // 2. ถ้าไม่มี Token ส่ง Status 401 กลับไป
    if (!token) return res.status(401).json({ message: "คุณไม่มีสิทธิ์เข้าถึง! (กรุณาล็อกอิน)" });

    // 3. อ่าน Token ว่าถูกต้องหรือหมดอายุไหม
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        // หาก Token ไม่ถูกต้อง
        if (err) return res.status(403).json({ message: "Token ไม่ถูกต้อง หรือหมดอายุ!" });

        // หากถูกต้อง อนุญาตให้ทำคำสั่งถัดไปได้
        req.user = decoded; // จัดเก็บรหัส User ไว้เผื่อใช้
        next();
    });
};

// ... (จะเขียน API ทั้ง 4 เส้นทางตำแหน่งนี้) ...

// READ (GET): ขอดูงานทั้งหมดในตู้เซฟ
// สังเกต: มีคำว่า async หน้า (req, res)
app.get('/tasks', async (req, res) => {
    try {
        // await สั่งให้โปรแกรม "รอ" จนกว่าเสมียนจะไปกวาดข้อมูลจาก Cloud กลับมาเสร็จ
        const tasks = await Task.find();
        res.json(tasks); // ส่ง Array ข้อมูลกลับไปให้ผู้ใช้
    } catch (err) {
        // ถ้าเน็ตหลุด หรือตู้เซฟพัง จะกระโดดมาตรงนี้ (Server ไม่พัง)
        res.status(500).json({ message: "ระบบฐานข้อมูลขัดข้อง", error: err.message });
    }
});

// CREATE (POST): สร้างงานใหม่
app.post('/tasks', async (req, res) => {
    try {
        // นำข้อมูลที่ส่งมา (req.body) ไปใส่แบบฟอร์มพิมพ์เขียว
        const newTask = new Task({
            title: req.body.title,
            priority: req.body.priority
        });

        // สั่งบันทึกลง Database (ต้องรอให้เซฟเสร็จก่อน)
        await newTask.save();

        // ตอบกลับไปว่าสร้างสำเร็จ
        res.status(201).json({ message: "บันทึกสำเร็จ!", task: newTask });
    } catch (err) {
        // เช่น ถ้าผู้ใช้ไม่ส่ง title มา (ผิดกฎ Schema) Mongoose จะส่งข้อผิดพลาดมาเข้ากล่องนี้
        res.status(400).json({ message: "ข้อมูลไม่ถูกต้อง", error: err.message });
    }
});

// UPDATE (PUT): แก้ไขสถานะงาน (เสร็จ/ไม่เสร็จ)
app.put('/tasks/:id', async (req, res) => {
    try {
        // ค้นหางานด้วย _id
        const task = await Task.findById(req.params.id);

        // หากหา _id ไม่เจอ ให้ตอบกลับว่าไม่พบข้อมูล
        if (!task) {
            return res.status(404).json({ message: "ไม่พบงานหมายเลขนี้" });
        }

        // สลับค่า Boolean (ถ้า true ให้เป็น false / ถ้า false ให้เป็น true)
        task.completed = !task.completed;

        // บันทึกทับลง Database
        await task.save();

        res.json({ message: "อัปเดตสถานะสำเร็จ", task: task });
    } catch (err) {
        res.status(500).json({ message: "ID ผิดรูปแบบ หรือระบบขัดข้อง" });
    }
});

// DELETE (ลบงาน)
app.delete('/tasks/:id', verifyToken, async (req, res) => {
    try {
        // คำสั่งเดียวจบ: ค้นหาด้วย _id แล้วลบทิ้งทันที
        const deletedTask = await Task.findByIdAndDelete(req.params.id);

        if (!deletedTask) {
            return res.status(404).json({ message: "ไม่พบงานหมายเลขนี้" });
        }

        res.json({ message: "ลบงานออกจากระบบเรียบร้อยแล้ว" });
    } catch (err) {
        res.status(500).json({ message: "ID ผิดรูปแบบ หรือระบบขัดข้อง" });
    }
});

app.listen(PORT, () => {
    console.log(`Server กําลังรันอยู่ที่พอร์ต ${PORT}`);
});