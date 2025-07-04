// =================================================================
// --- 1. DEPENDENCIES ---
// =================================================================
const express = require('express');
const OpenAI = require('openai');
const dotenv = require('dotenv');
const cors = require('cors');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { Queue, Worker } = require('bullmq');
const IORedis = require('ioredis');
const cron = require('node-cron');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, ImageRun } = require("docx");
const ExcelJS = require('exceljs');
const PptxGenJS = require('pptxgenjs');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const { createClient } = require('pexels');
const fetch = require('node-fetch');
const axios = require('axios');

// =================================================================
// --- 2. INITIALIZATION & CONFIG ---
// =================================================================
dotenv.config();
const app = express();
app.use(cors()); // Enable CORS early

// Special raw body parser for Stripe webhook, must come before app.use(express.json())
app.post('/api/payments/nowpayments-webhook', express.raw({type: 'application/json'}), async (req, res) => {
    try {
        const { payment_status, order_id, payment_id } = req.body;

        if (payment_status === 'finished') {
            const userId = order_id.split('-')[2];
            const user = await User.findById(userId);

            if (user) {
                user.subscription.status = 'pro';
                const periodEnd = new Date();
                periodEnd.setDate(periodEnd.getDate() + 31);
                user.subscription.periodEnd = periodEnd;
                user.subscription.lastPaymentId = payment_id;
                
                await user.save();
                console.log(`[SUCCESS] Pro subscription activated for user: ${user.email}`);
            }
        }
        res.status(200).send('Webhook received.');
    } catch (error) {
        console.error('[Webhook Error]', error);
        res.status(500).send('Error processing webhook.');
    }
});


app.use(express.json({ limit: '50mb' }));
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "script-src 'self' https://challenges.cloudflare.com");
    next();
});

// =================================================================
// --- 3. DATABASE & SERVICE CONNECTIONS ---
// =================================================================
mongoose.connect(process.env.DATABASE_URL)
    .then(() => console.log('[SUCCESS] Connected to MongoDB Atlas.'))
    .catch(err => console.error('[FATAL] Could not connect to MongoDB Atlas.', err));

const redisConnection = new IORedis({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
    password: process.env.REDIS_PASSWORD,
    maxRetriesPerRequest: null
});
redisConnection.on('connect', () => console.log('[SUCCESS] Connected to Redis.'));
redisConnection.on('error', err => console.error('[FATAL] Redis connection error.', err));

const agentQueue = new Queue('agentTasks', { connection: redisConnection });

// =================================================================
// --- 4. API KEY & CLIENT SETUP ---
// =================================================================
if (!process.env.OPENAI_API_KEY || !process.env.PEXELS_API_KEY || !process.env.DATABASE_URL || !process.env.JWT_SECRET || !process.env.BREVO_API_KEY || !process.env.SENDER_EMAIL_ADDRESS || !process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY || !process.env.REDIS_HOST) {
    console.error("FATAL ERROR: One or more critical environment variables are missing. Please check your .env file.");
    process.exit(1);
}
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const pexelsClient = createClient(process.env.PEXELS_API_KEY);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const personas = {
    general: 'You are a helpful, general-purpose assistant.',
    coding: 'You are a world-class software engineer.',
    professional: 'You are a highly analytical business consultant.',
    academic: 'You are an elite academic researcher.'
};


// =================================================================
// --- 5. DATABASE SCHEMAS & MODELS ---
// =================================================================
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    role: { type: String, enum: ['user', 'super_admin'], default: 'user' },
    subscription: {
        status: { type: String, enum: ['free', 'pro'], default: 'free' },
        periodEnd: { type: Date },
        lastPaymentId: { type: String }
    }
});
const User = mongoose.model('User', userSchema);

const profileSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    customInstructions: { type: String, default: '' }
});
const Profile = mongoose.model('Profile', profileSchema);

const agentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    prompt: { type: String, required: true },
    schedule: { type: String, required: true },
    lastRun: { type: Date, default: null },
    nextRun: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true }
});
const Agent = mongoose.model('Agent', agentSchema);

const actionLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    actionType: { type: String, required: true },
    details: { type: Object },
    timestamp: { type: Date, default: Date.now }
});
const ActionLog = mongoose.model('ActionLog', actionLogSchema);

const suggestionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    description: { type: String, required: true },
    action: { type: Object, required: true },
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now, expires: '7d' }
});
const Suggestion = mongoose.model('Suggestion', suggestionSchema);

const feedbackSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    chatId: { type: String, required: true },
    messageContent: { type: String, required: true },
    rating: { type: String, enum: ['positive', 'negative'], required: true },
    comment: { type: String },
    timestamp: { type: Date, default: Date.now }
});
const Feedback = mongoose.model('Feedback', feedbackSchema);


// =================================================================
// --- 6. MIDDLEWARE ---
// =================================================================
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required: No token provided.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Authentication failed: Invalid token.' });
    }
};

const verifyTurnstile = async (req, res, next) => {
    const token = req.body.turnstileToken;
    if (!token) {
        return res.status(400).json({ error: 'CAPTCHA token is missing.' });
    }
    const verificationURL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    try {
        const response = await fetch(verificationURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${encodeURIComponent(process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY)}&response=${encodeURIComponent(token)}`
        });
        const data = await response.json();
        if (data.success) {
            next();
        } else {
            res.status(403).json({ error: 'Failed CAPTCHA verification.' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error during CAPTCHA verification.' });
    }
};

// =================================================================
// --- IN-MEMORY JOB STORAGE for file download links ---
// =================================================================
const jobs = {};

// --- End of Part 1 ---
// --- Start of Part 2 ---

// =================================================================
// --- 7. HELPER & BACKGROUND FUNCTIONS ---
// =================================================================
async function getAdvancedSystemPrompt(personaArray, customInstructions, emotion) {
    let personaPrompt = personas.general;
    if (personaArray && personaArray.length > 0) {
        if (personaArray.length === 1) { personaPrompt = personas[personaArray[0]] || personas.general; }
        else { personaPrompt = `You are a multi-disciplinary expert combining: ${personaArray.map(p => personas[p]).join(', ')}.`; }
    }
    const customInstructionBlock = customInstructions ? `\n\n--- USER'S PERMANENT INSTRUCTIONS ---\n${customInstructions}\n---` : '';
    let emotionalAdjustment = '';
    if (emotion) {
        switch (emotion) {
            case 'frustrated': emotionalAdjustment = `\n\n[EMOTIONAL CONTEXT]: The user seems frustrated. Be especially patient and helpful.`; break;
            case 'happy': emotionalAdjustment = `\n\n[EMOTIONAL CONTEXT]: The user seems happy. Use a friendly tone.`; break;
        }
    }
    const metaCognitionInstruction = `\n\n[META-COGNITION]: After your main response, append a special single-line JSON object that describes your thought process in the format: [META:{"thought_process":["Step 1: ...", "Step 2: ..."]}]`;
    return `${personaPrompt}${customInstructionBlock}${emotionalAdjustment}${metaCognitionInstruction}\nIMPORTANT INSTRUCTIONS:\n1. Provide comprehensive answers.\n2. Suggest follow-up questions.`;
}

async function fetchImage(query) { /* ... same as previous final version ... */ }
async function generateStructuredDocument(userRequest, language, persona, customInstructions) { /* ... same as previous final version ... */ }
async function generateStructuredPowerPoint(userRequest, language, persona, customInstructions) { /* ... same as previous final version ... */ }
async function generateStructuredExcel(userRequest, language, persona, customInstructions) { /* ... same as previous final version ... */ }
async function analyzeAndImprove(userId, feedback) { /* ... same as previous final version ... */ }

// --- BACKGROUND WORKERS & SCHEDULERS ---
const agentWorker = new Worker('agentTasks', async job => { /* ... same as previous final version ... */ }, { connection: redisConnection });
cron.schedule('0 * * * *', async () => { /* ... Agent execution cron logic ... */ });
cron.schedule('0 */2 * * *', async () => { /* ... Suggestion generation cron logic ... */ });


// =================================================================
// --- 8. API ROUTER & ENDPOINTS ---
// =================================================================
const apiRouter = express.Router();

// --- Auth Endpoints ---
apiRouter.post('/auth/register', verifyTurnstile, async (req, res) => {
    try {
        const { email, password } = req.body;
        // Password complexity check
        if (!email || !password || password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
            return res.status(400).json({ error: 'Password does not meet complexity requirements.' });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(409).json({ error: 'User with this email already exists.' });
        
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
        await new Profile({ userId: newUser._id }).save();
        res.status(201).json({ message: 'User registered successfully. Please login.' });
    } catch (error) { res.status(500).json({ error: 'Server error during registration.' }); }
});

apiRouter.post('/auth/login', verifyTurnstile, async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials.' });
        const expiresIn = rememberMe ? '30d' : '24h';
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn });
        res.json({ token, email: user.email, subscription: user.subscription });
    } catch (error) { res.status(500).json({ error: 'Server error during login.' }); }
});

// --- Protected Feature Endpoints ---
apiRouter.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const profile = await Profile.findOne({ userId: req.user.id });
        res.json({ profile, subscription: user.subscription });
    } catch (error) { res.status(500).json({ error: 'Could not fetch profile.' }); }
});

apiRouter.post('/profile', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.get('/agents', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.post('/agents', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.delete('/agents/:id', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.get('/suggestions', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.post('/suggestions/:id/execute', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.delete('/suggestions/:id', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.post('/feedback', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });
apiRouter.post('/summarize', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });

// --- End of Part 2 ---
// --- Start of Part 3 ---

// --- Main Feature Endpoints (Continued) ---

// Chat Endpoint
apiRouter.post('/chat', authMiddleware, async (req, res) => {
    try {
        const profile = await Profile.findOne({ userId: req.user.id });
        const { message, persona, chatHistory, image, emotion } = req.body;
        res.setHeader('Content-Type', 'text/event-stream');
        res.flushHeaders();
        const systemPrompt = await getAdvancedSystemPrompt(persona, profile.customInstructions, emotion);
        const userMessageContent = [{ type: 'text', text: message }];
        if (image) userMessageContent.push({ type: 'image_url', image_url: { url: image } });
        const messages = [{ role: 'system', content: systemPrompt }, ...chatHistory, { role: 'user', content: userMessageContent }];
        const stream = await openai.chat.completions.create({ model: 'gpt-4o', messages, stream: true });
        for await (const chunk of stream) {
            res.write(`data: ${JSON.stringify({ content: chunk.choices[0]?.delta?.content || '' })}\n\n`);
        }
    } catch (error) { res.write(`data: ${JSON.stringify({ error: 'Chat error.' })}\n\n`); }
    finally { res.write(`data: [DONE]\n\n`); res.end(); }
});

// Asynchronous File Generation Endpoint
apiRouter.post('/generate/stream', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const isPro = user.role === 'super_admin' || (user.subscription && user.subscription.status === 'pro' && new Date() < new Date(user.subscription.periodEnd));
        // Simple usage limit for free users - can be expanded
        const monthlyUsage = await ActionLog.countDocuments({ userId: req.user.id, actionType: 'generate_file', timestamp: { $gte: new Date(new Date().setDate(new Date().getDate() - 30)) } });
        
        if (!isPro && monthlyUsage >= 5) {
            return res.status(403).json({ error: 'You have exceeded your monthly limit for file generation. Please upgrade to Pro.' });
        }

        res.setHeader('Content-Type', 'text/event-stream');
        res.flushHeaders();
        const { type, topic, language, persona } = req.body;
        processFileGeneration(res, type, topic, language, persona, req.user.id);
    } catch (error) {
         res.status(500).json({ error: 'Failed to start generation job.' });
    }
});

// Main Background Processing Function
async function processFileGeneration(res, type, topic, language, persona, userId) {
    const sendStatus = (status, progress = '') => res.write(`data: ${JSON.stringify({ status, progress })}\n\n`);
    try {
        // ... (Full logic from previous versions to generate file and log action) ...
        // ... (The email notification logic is also here) ...
    } catch (error) {
        console.error(`File Generation Error for job:`, error);
        res.write(`data: ${JSON.stringify({ error: 'Failed to generate file.' })}\n\n`);
    } finally {
        res.write(`data: [DONE]\n\n`);
        res.end();
    }
}

// Convert File Endpoint
apiRouter.post('/convert/file', authMiddleware, upload.single('file'), async (req, res) => { /* ... The final high-precision version ... */ });

// Payment Endpoints
apiRouter.post('/payments/create-invoice', authMiddleware, async (req, res) => { /* ... same as previous final version ... */ });


app.use('/api', apiRouter);

// =================================================================
// --- 9. SERVE FRONTEND & START SERVER ---
// =================================================================
app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[SUCCESS] Smart AI is running on http://localhost:${PORT}`);
});

// --- End of Part 3 ---

