const express = require('express');
const bcrypt = require('bcrypt');
const fileUpload = require('express-fileupload');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const secret = process.env.SECRET;
const saltRounds = 10;

// -------------------- MongoDB Connection --------------------
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB connected successfully'))
    .catch(err => console.error('MongoDB connection error:', err));

// -------------------- Session Store in MongoDB --------------------
const store = new MongoDBStore({
    uri: MONGO_URI,
    collection: 'sessions',
    expires: 365 * 24 * 60 * 60 * 1000 // 1 year
});
store.on('error', error => console.error('Session store error:', error));

// -------------------- Middleware --------------------
app.use(fileUpload({
    limits: { fileSize: 5 * 1024 * 1024 }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    secret: secret,
    resave: false,
    saveUninitialized: false,
    store: store,                     // <-- now persistent
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 365 * 24 * 60 * 60 * 1000
    }
}));

// -------------------- Mongoose Models --------------------
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const fileSchema = new mongoose.Schema({
    filename: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    uploadedAt: { type: Date, default: Date.now }
});
const File = mongoose.model('File', fileSchema);

// -------------------- Routes --------------------

// Home – show all files
app.get('/', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    try {
        const user = await User.findById(req.session.userId);
        const files = await File.find().sort({ uploadedAt: -1 });
        res.render('index', { user, files });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Auth pages
app.get('/signup', (req, res) => res.render('signup'));
app.get('/login', (req, res) => res.render('login'));

// Upload page
app.get('/upload', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.render('upload', { user: req.session.userId });
});

// Dashboard – user's own files
app.get('/dashboard', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    try {
        const user = await User.findById(req.session.userId);
        const myFiles = await File.find({ userId: user._id }).sort({ uploadedAt: -1 });
        res.render('dashboard', { user, files: myFiles });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// ---- Auth handlers ----
app.post('/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const existingEmail = await User.findOne({ email });
        if (existingEmail) return res.status(400).send('Email already exists');
        const existingName = await User.findOne({ name });
        if (existingName) return res.status(400).send('Name already exists');

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();

        req.session.userId = user._id;
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error during signup');
    }
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('User not found');

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).send('Incorrect password');

        req.session.userId = user._id;
        req.session.isLoggedIn = true;
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error during login');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Logout failed');
        res.redirect('/login');
    });
});

// ---- File upload ----
app.post('/event/uploads', async (req, res) => {
    if (!req.session.userId) return res.status(401).send('You must be logged in to upload');

    const { title, description } = req.body;
    if (!title) return res.status(400).send('Title is required');
    if (!req.files || !req.files.htmlFile) return res.status(400).send('No file uploaded.');

    const file = req.files.htmlFile;
    const uploadDir = './uploads';

    try {
        if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

        const user = await User.findById(req.session.userId);
        const newFile = new File({
            filename: file.name,
            title,
            description: description || '',
            userId: user._id
        });
        await newFile.save();

        const newFileName = `${newFile._id}.html`;
        const uploadPath = path.join(uploadDir, newFileName);
        await file.mv(uploadPath);

        res.redirect('/');
    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).send('Error saving file.');
    }
});

// ---- Delete file ----
app.post('/file/delete/:id', async (req, res) => {
    if (!req.session.userId) return res.status(401).send('Unauthorized');

    const fileId = req.params.id;
    try {
        const file = await File.findById(fileId);
        if (!file) return res.status(404).send('File not found');
        if (file.userId.toString() !== req.session.userId)
            return res.status(403).send('You do not own this file');

        const filePath = path.join(__dirname, 'uploads', `${file._id}.html`);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

        await File.findByIdAndDelete(fileId);
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error deleting file');
    }
});

// ---- Re‑upload (replace content) ----
app.post('/file/reupload/:id', async (req, res) => {
    if (!req.session.userId) return res.status(401).send('Unauthorized');

    const fileId = req.params.id;
    if (!req.files || !req.files.htmlFile)
        return res.status(400).send('No file uploaded.');

    try {
        const fileDoc = await File.findById(fileId);
        if (!fileDoc) return res.status(404).send('File not found');
        if (fileDoc.userId.toString() !== req.session.userId)
            return res.status(403).send('You do not own this file');

        const newFile = req.files.htmlFile;
        const filePath = path.join(__dirname, 'uploads', `${fileDoc._id}.html`);
        await newFile.mv(filePath);

        fileDoc.filename = newFile.name;
        await fileDoc.save();

        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error re-uploading file');
    }
});

// ---- Serve file ----
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    const safeFilename = path.basename(filename);
    const filePath = path.join(__dirname, 'uploads', safeFilename);

    res.sendFile(filePath, err => {
        if (err) res.status(404).send('File not found');
    });
});

// -------------------- Start Server --------------------
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
