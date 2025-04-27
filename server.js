// --- server.js (Sửa theo Cách 2 - Serve static từ thư mục gốc) ---

import express from 'express';
import path from 'path';
import pg from 'pg';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

// --- Configuration ---
const app = express();
const PORT = process.env.PORT || 3001;

// Helper to get __dirname equivalent in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
console.log(`[Server Init] Running from directory: ${__dirname}`);

// --- Database Setup ---
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test DB connection on startup
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error("!!! [DB Connection] Failed to connect to database on startup:", err);
    } else {
        console.log("[DB Connection] Database connected successfully at:", res.rows[0].now);
    }
});

const SESSION_TIMEOUT_MINUTES = 10;

// --- Middleware ---
app.use(express.json());

// *** THAY ĐỔI QUAN TRỌNG: Serve static files từ thư mục gốc (__dirname) ***
// Cảnh báo: Điều này có thể làm lộ các file không mong muốn nếu không cẩn thận.
// Đảm bảo .env, node_modules, server.js không bị phục vụ (Express thường bỏ qua .js, nhưng cần cẩn thận)
// Cân nhắc thêm tùy chọn `dotfiles: 'ignore'` để tránh lộ file ẩn.
app.use(express.static(__dirname, { dotfiles: 'ignore' }));
console.log(`[Server Init] Serving static files from root directory: ${__dirname}`);


// --- Helper Functions ---
function generateSecureRandomString(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// --- API Routes (Giữ nguyên như trước) ---

// 1. Authentication Endpoint
app.post('/api/authenticate', async (req, res) => {
    const { accessCode } = req.body;
    console.log(`[API /authenticate] Received code: ${accessCode}`);
    if (!accessCode) return res.status(400).json({ success: false, message: 'Mã truy cập là bắt buộc.' });

    let client;
    try {
        client = await pool.connect();
        const result = await client.query('SELECT * FROM access_codes WHERE code = $1', [accessCode]);
        if (result.rows.length === 0) {
            console.log(`[API /authenticate] Code not found: ${accessCode}`);
            return res.status(401).json({ success: false, message: 'Mã truy cập không hợp lệ.' });
        }
        const codeData = result.rows[0];
        if (!codeData.is_active) {
            console.log(`[API /authenticate] Code inactive: ${accessCode}`);
            return res.status(403).json({ success: false, message: 'Mã truy cập đã bị vô hiệu hóa.' });
        }
        const now = new Date();
        const timeoutThreshold = new Date(now.getTime() - SESSION_TIMEOUT_MINUTES * 60000);
        if (codeData.current_session_id && codeData.last_ping_time && codeData.last_ping_time > timeoutThreshold) {
            console.log(`[API /authenticate] Code already in use: ${accessCode}.`);
            return res.status(409).json({ success: false, message: 'Mã truy cập này đang được sử dụng bởi một thiết bị khác.' });
        }
        const newSessionId = generateSecureRandomString();
        const updateResult = await client.query(
            'UPDATE access_codes SET current_session_id = $1, last_ping_time = NOW() WHERE code = $2 RETURNING referrer_code',
            [newSessionId, accessCode]
        );
        if (updateResult.rowCount === 0) {
             console.error(`[API /authenticate] Failed to update session for code: ${accessCode}`);
             return res.status(500).json({ success: false, message: 'Lỗi cập nhật phiên đăng nhập.' });
        }
        console.log(`[API /authenticate] Success! Code: ${accessCode}, New Session: ${newSessionId}`);
        res.json({
            success: true, sessionId: newSessionId, userName: codeData.user_name,
            referrerCode: updateResult.rows[0]?.referrer_code
        });
    } catch (err) {
        console.error('[API /authenticate] Error:', err);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ khi xác thực.' });
    } finally {
        client?.release();
    }
});

// 2. Session Ping Endpoint
app.post('/api/ping', async (req, res) => {
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ success: false, message: 'Session ID là bắt buộc.' });
    let client;
    try {
        client = await pool.connect();
        const result = await client.query('UPDATE access_codes SET last_ping_time = NOW() WHERE current_session_id = $1 RETURNING code', [sessionId]);
        if (result.rowCount > 0) res.json({ success: true });
        else { console.log(`[API /ping] Session ID not found or expired: ${sessionId}`); res.status(401).json({ success: false, message: 'Phiên không hợp lệ hoặc đã hết hạn.' }); }
    } catch (err) { console.error('[API /ping] Database error:', err); res.status(500).json({ success: false, message: 'Lỗi máy chủ khi ping.' }); }
    finally { client?.release(); }
});

// 3. Logout Endpoint
app.post('/api/logout', async (req, res) => {
    const { sessionId } = req.body;
    console.log(`[API /logout] Received logout request for session: ${sessionId}`);
    if (!sessionId) return res.status(400).json({ success: false, message: 'Session ID là bắt buộc.' });
    let client;
    try {
        client = await pool.connect();
        const result = await client.query('UPDATE access_codes SET current_session_id = NULL, last_ping_time = NULL WHERE current_session_id = $1 RETURNING code', [sessionId]);
        if (result.rowCount > 0) console.log(`[API /logout] Session ${sessionId} (Code: ${result.rows[0].code}) logged out.`);
        else console.log(`[API /logout] Session ID not found or already logged out: ${sessionId}`);
        res.json({ success: true }); // Always success from client perspective
    } catch (err) { console.error('[API /logout] Database error:', err); res.status(500).json({ success: false, message: 'Lỗi máy chủ khi đăng xuất.' }); }
    finally { client?.release(); }
});

// 4. Admin: Generate Code Endpoint (NEEDS REAL SECURITY)
app.post('/api/generate_code', async (req, res) => {
    const { adminSecret, referrerCode, userName } = req.body;
    if (!process.env.ADMIN_SECRET_KEY || adminSecret !== process.env.ADMIN_SECRET_KEY) {
        console.warn('[API /generate_code] Unauthorized attempt.');
        return res.status(403).json({ success: false, message: 'Không có quyền.' });
    }
    if (referrerCode && typeof referrerCode !== 'string') return res.status(400).json({ success: false, message: 'Mã người giới thiệu không hợp lệ.' });
    const newCode = `REF_${generateSecureRandomString(8)}`;
    let client;
    try {
        client = await pool.connect();
        if (referrerCode) {
            const referrerCheck = await client.query('SELECT 1 FROM access_codes WHERE code = $1 AND is_active = TRUE', [referrerCode]);
            if (referrerCheck.rowCount === 0) return res.status(400).json({ success: false, message: `Mã người giới thiệu '${referrerCode}' không tồn tại hoặc không hoạt động.` });
        }
        await client.query('INSERT INTO access_codes (code, referrer_code, user_name, is_active) VALUES ($1, $2, $3, TRUE)', [newCode, referrerCode || null, userName || `User_${newCode.substring(0, 5)}`]);
        console.log(`[API /generate_code] Generated new code: ${newCode}, Referrer: ${referrerCode || 'None'}, User: ${userName || `User_${newCode.substring(0, 5)}`}`);
        res.status(201).json({ success: true, newCode: newCode });
    } catch (err) {
        console.error('[API /generate_code] Database error:', err);
        if (err.code === '23505') return res.status(409).json({ success: false, message: 'Lỗi tạo mã trùng lặp, vui lòng thử lại.' });
        res.status(500).json({ success: false, message: 'Lỗi máy chủ khi tạo mã.' });
    } finally {
        client?.release();
    }
});


// --- Serve Frontend (Catch-all Route) ---
// Phục vụ index.html cho mọi request GET không khớp với API hoặc file tĩnh khác
app.get('*', (req, res) => {
    // Kiểm tra xem request có yêu cầu file cụ thể không (ví dụ: .css, .js, .png)
    // Nếu không phải file tĩnh đã được xử lý bởi express.static, thì trả về index.html
    if (!path.extname(req.path) || req.path === '/') { // Check if no extension or root path
         console.log(`[Serve Frontend] Serving index.html for request: ${req.path}`);
         res.sendFile(path.join(__dirname, 'index.html')); // *** THAY ĐỔI: Tìm index.html ở gốc ***
    } else {
         // Nếu request có phần mở rộng nhưng express.static không tìm thấy
         // (ví dụ: file không tồn tại), trả về lỗi 404
          console.log(`[Serve Frontend] Static file not found by express.static: ${req.path}`);
         res.status(404).send('Not Found');
    }
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`[Server Start] Server listening on port ${PORT}`);
});
