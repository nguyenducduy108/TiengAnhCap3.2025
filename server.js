import {
    Card,
    CardBody,
    CardFooter,
    Typography,
    Button,
  } from "@material-tailwind/react";
   
  export function SimpleCard() {
    return (
      <Card className="mt-6 w-96">
        <CardBody>
          <Typography variant="h5" color="blue-gray" className="mb-2">
            UI/UX Review Check
          </Typography>
          <Typography>
            The place is close to Barceloneta Beach and bus stop just 2 min by
            walk and near to "Naviglio" where you can enjoy the main
            night life in Barcelona.
          </Typography>
        </CardBody>
        <CardFooter className="pt-0">
          <Button>Read More</Button>
        </CardFooter>
      </Card>
    );
  }

const path = require('path');
const express = require('express');
const { Pool } = require('pg'); // PostgreSQL client
const crypto = require('crypto'); // For generating secure random strings (session IDs, maybe codes)
require('dotenv').config(); // To load .env file for local development

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 3001;
// Ensure DATABASE_URL is set in Render environment variables (Internal URL)
// For local dev, set it in your .env file (e.g., postgresql://user:password@host:port/database)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false // Necessary for Render DB connections
});

const SESSION_TIMEOUT_MINUTES = 10; // How long a session is considered active without a ping

// --- Database Schema (Run this SQL manually or via migration tool ONCE) ---
/*
-- Recommended table structure
CREATE TABLE IF NOT EXISTS access_codes (
    code VARCHAR(100) PRIMARY KEY,          -- The unique access code
    referrer_code VARCHAR(100) REFERENCES access_codes(code) ON DELETE SET NULL, -- Code of the referrer (optional)
    user_name VARCHAR(255),                -- Optional: User's name/identifier
    is_active BOOLEAN DEFAULT TRUE,        -- Can this code be used?
    current_session_id VARCHAR(128) UNIQUE, -- The ID of the current active session using this code (NULL if not logged in)
    last_ping_time TIMESTAMPTZ             -- Timestamp of the last ping from the active session
);

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_access_codes_session_id ON access_codes(current_session_id);
CREATE INDEX IF NOT EXISTS idx_access_codes_referrer ON access_codes(referrer_code);

-- Example of adding an initial code (replace with your actual code/method)
-- INSERT INTO access_codes (code, user_name) VALUES ('INITIALCODE123', 'Admin User') ON CONFLICT (code) DO NOTHING;
*/

// --- Middleware ---
app.use(express.json()); // Parse JSON request bodies
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files (HTML, CSS, JS) from 'public' folder

// --- Helper Functions ---
function generateSecureRandomString(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// --- API Routes ---

// 1. Authentication Endpoint
app.post('/api/authenticate', async (req, res) => {
    const { accessCode } = req.body;
    console.log(`[API /authenticate] Received code: ${accessCode}`);

    if (!accessCode) {
        return res.status(400).json({ success: false, message: 'Mã truy cập là bắt buộc.' });
    }

    let client; // Declare client outside try block
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

        // Check for concurrent access
        const now = new Date();
        const timeoutThreshold = new Date(now.getTime() - SESSION_TIMEOUT_MINUTES * 60000);

        // If there's a session ID AND the last ping was within the timeout period
        if (codeData.current_session_id && codeData.last_ping_time && codeData.last_ping_time > timeoutThreshold) {
            console.log(`[API /authenticate] Code already in use: ${accessCode}. Last ping: ${codeData.last_ping_time}`);
            return res.status(409).json({ success: false, message: 'Mã truy cập này đang được sử dụng bởi một thiết bị khác.' });
        }

        // --- Authentication successful ---
        const newSessionId = generateSecureRandomString();
        const updateResult = await client.query(
            'UPDATE access_codes SET current_session_id = $1, last_ping_time = NOW() WHERE code = $2 RETURNING referrer_code',
            [newSessionId, accessCode]
        );

        console.log(`[API /authenticate] Success! Code: ${accessCode}, New Session: ${newSessionId}`);
        res.json({
            success: true,
            sessionId: newSessionId, // Send session ID to client
            userName: codeData.user_name, // Optional: Send user info
            referrerCode: updateResult.rows[0]?.referrer_code // Send referrer if exists
        });

    } catch (err) {
        console.error('[API /authenticate] Database error:', err);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ khi xác thực.' });
    } finally {
        client?.release(); // Release the client back to the pool
    }
});

// 2. Session Ping Endpoint
app.post('/api/ping', async (req, res) => {
    const { sessionId } = req.body; // Client sends its current session ID

    if (!sessionId) {
        return res.status(400).json({ success: false, message: 'Session ID là bắt buộc.' });
    }

    let client;
    try {
        client = await pool.connect();
        // Find the code associated with this session ID and update its ping time
        const result = await client.query(
            'UPDATE access_codes SET last_ping_time = NOW() WHERE current_session_id = $1 RETURNING code',
            [sessionId]
        );

        if (result.rowCount > 0) {
            // console.log(`[API /ping] Session ${sessionId} (Code: ${result.rows[0].code}) pinged successfully.`);
            res.json({ success: true }); // Ping successful
        } else {
            console.log(`[API /ping] Session ID not found or expired: ${sessionId}`);
            res.status(401).json({ success: false, message: 'Phiên không hợp lệ hoặc đã hết hạn.' }); // Session not found or already cleared
        }
    } catch (err) {
        console.error('[API /ping] Database error:', err);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ khi ping.' });
    } finally {
        client?.release();
    }
});

// 3. Logout Endpoint
app.post('/api/logout', async (req, res) => {
    const { sessionId } = req.body;
    console.log(`[API /logout] Received logout request for session: ${sessionId}`);


    if (!sessionId) {
        return res.status(400).json({ success: false, message: 'Session ID là bắt buộc.' });
    }

    let client;
    try {
        client = await pool.connect();
        // Clear the session ID and ping time for the corresponding code
        const result = await client.query(
            'UPDATE access_codes SET current_session_id = NULL, last_ping_time = NULL WHERE current_session_id = $1 RETURNING code',
            [sessionId]
        );

        if (result.rowCount > 0) {
            console.log(`[API /logout] Session ${sessionId} (Code: ${result.rows[0].code}) logged out successfully.`);
            res.json({ success: true });
        } else {
             // Session might have already expired or was invalid
            console.log(`[API /logout] Session ID not found or already logged out: ${sessionId}`);
            res.json({ success: true }); // Still return success as the goal (no active session) is achieved
        }
    } catch (err) {
        console.error('[API /logout] Database error:', err);
        res.status(500).json({ success: false, message: 'Lỗi máy chủ khi đăng xuất.' });
    } finally {
        client?.release();
    }
});

// 4. Admin: Generate Code Endpoint (Needs proper security in a real app!)
// WARNING: This is a simplified example. In production, you NEED robust authentication
// and authorization (e.g., check if the request comes from an admin user).
// Using a simple secret key here is NOT secure for production.
app.post('/api/generate_code', async (req, res) => {
    const { adminSecret, referrerCode, userName } = req.body;

    // --- VERY BASIC SECURITY CHECK - REPLACE WITH REAL AUTH ---
    if (adminSecret !== process.env.ADMIN_SECRET_KEY) { // Set ADMIN_SECRET_KEY in your .env / Render env vars
        console.warn('[API /generate_code] Unauthorized attempt.');
        return res.status(403).json({ success: false, message: 'Không có quyền.' });
    }
    // --- END BASIC SECURITY CHECK ---

    if (referrerCode && typeof referrerCode !== 'string') {
         return res.status(400).json({ success: false, message: 'Mã người giới thiệu không hợp lệ.' });
    }

    const newCode = `REF_${generateSecureRandomString(8)}`; // Example code format
    let client;

    try {
        client = await pool.connect();

        // Optional: Check if referrerCode actually exists if provided
        if (referrerCode) {
            const referrerCheck = await client.query('SELECT 1 FROM access_codes WHERE code = $1', [referrerCode]);
            if (referrerCheck.rowCount === 0) {
                 return res.status(400).json({ success: false, message: `Mã người giới thiệu '${referrerCode}' không tồn tại.` });
            }
        }

        // Insert the new code
        await client.query(
            'INSERT INTO access_codes (code, referrer_code, user_name, is_active) VALUES ($1, $2, $3, TRUE)',
            [newCode, referrerCode || null, userName || `User_${newCode}`] // Use NULL if no referrer
        );

        console.log(`[API /generate_code] Generated new code: ${newCode}, Referrer: ${referrerCode || 'None'}, User: ${userName || `User_${newCode}`}`);
        res.status(201).json({ success: true, newCode: newCode });

    } catch (err) {
        console.error('[API /generate_code] Database error:', err);
        // Handle potential unique constraint violation if generated code already exists (rare)
        if (err.code === '23505') { // Unique violation code for PostgreSQL
             return res.status(409).json({ success: false, message: 'Lỗi tạo mã trùng lặp, vui lòng thử lại.' });
        }
        res.status(500).json({ success: false, message: 'Lỗi máy chủ khi tạo mã.' });
    } finally {
        client?.release();
    }
});


// --- Serve Frontend ---
// Route to catch all other GET requests and serve the main HTML file
// This allows client-side routing (if you use hashes #module1, #test1 etc.) to work correctly
// Put this LAST, after all API routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    // Optional: Check DB connection on startup
    pool.query('SELECT NOW()', (err, res) => {
        if (err) {
            console.error("!!! Failed to connect to database on startup:", err);
        } else {
            console.log("Database connected successfully at:", res.rows[0].now);
        }
    });
});
