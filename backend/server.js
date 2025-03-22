require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(helmet());
app.use(cors());
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    
    
})
    .then(() => console.log('MongoDB connected'))
    .catch(error => {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    });

// Email Transporter Setup
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Schemas
const contactSchema = new mongoose.Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});
const Contact = mongoose.model('Contact', contactSchema);

const subscriptionSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    subscribedAt: { type: Date, default: Date.now },
});
const Subscription = mongoose.model('Subscription', subscriptionSchema);

const blogSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: String, default: 'Kimberley Msengezi' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date },
});
const Blog = mongoose.model('Blog', blogSchema);

const projectSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    image: { type: String },
    createdAt: { type: Date, default: Date.now },
});
const Project = mongoose.model('Project', projectSchema);

const testimonialSchema = new mongoose.Schema({
    content: { type: String, required: true },
    author: { type: String, required: true },
    role: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});
const Testimonial = mongoose.model('Testimonial', testimonialSchema);

const certificateSchema = new mongoose.Schema({
    title: { type: String, required: true },
    issuer: { type: String, required: true },
    image: { type: String },
    createdAt: { type: Date, default: Date.now },
});
const Certificate = mongoose.model('Certificate', certificateSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

// Middleware for JWT Authentication
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Middleware for Input Validation
const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    };
};

// Routes
// Contact Form Submission
app.post('/api/contact', validate([
    body('name').notEmpty().withMessage('Name is required'),
    body('phone').notEmpty().withMessage('Phone is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('message').notEmpty().withMessage('Message is required'),
]), async (req, res) => {
    const { name, phone, email, message } = req.body;

    try {
        const contact = new Contact({ name, phone, email, message });
        await contact.save();

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: 'New Contact Form Submission',
            text: `Name: ${name}\nPhone: ${phone}\nEmail: ${email}\nMessage: ${message}`,
        });

        res.status(201).json({ message: 'Message sent successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error sending message', error });
    }
});

// Email Subscription
app.post('/api/subscription', validate([
    body('email').isEmail().withMessage('Valid email is required'),
]), async (req, res) => {
    const { email } = req.body;

    try {
        const existingSubscription = await Subscription.findOne({ email });
        if (existingSubscription) {
            return res.status(400).json({ message: 'Email already subscribed' });
        }

        const subscription = new Subscription({ email });
        await subscription.save();

        res.status(201).json({ message: 'Subscribed successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error subscribing', error });
    }
});

// Blog Routes
app.get('/api/blog', async (req, res) => {
    try {
        const blogs = await Blog.find().sort({ createdAt: -1 });
        res.json(blogs);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching blogs', error });
    }
});

app.post('/api/blog', auth, validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('content').notEmpty().withMessage('Content is required'),
]), async (req, res) => {
    const { title, content } = req.body;

    try {
        const blog = new Blog({ title, content });
        await blog.save();
        res.status(201).json(blog);
    } catch (error) {
        res.status(500).json({ message: 'Error creating blog post', error });
    }
});

app.put('/api/blog/:id', auth, validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('content').notEmpty().withMessage('Content is required'),
]), async (req, res) => {
    const { title, content } = req.body;

    try {
        const blog = await Blog.findByIdAndUpdate(
            req.params.id,
            { title, content, updatedAt: Date.now() },
            { new: true }
        );
        if (!blog) {
            return res.status(404).json({ message: 'Blog post not found' });
        }
        res.json(blog);
    } catch (error) {
        res.status(500).json({ message: 'Error updating blog post', error });
    }
});

app.delete('/api/blog/:id', auth, async (req, res) => {
    try {
        const blog = await Blog.findByIdAndDelete(req.params.id);
        if (!blog) {
            return res.status(404).json({ message: 'Blog post not found' });
        }
        res.json({ message: 'Blog post deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting blog post', error });
    }
});

// Project Routes
app.get('/api/projects', async (req, res) => {
    try {
        const projects = await Project.find().sort({ createdAt: -1 });
        res.json(projects);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching projects', error });
    }
});

app.post('/api/projects', auth, validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('description').notEmpty().withMessage('Description is required'),
]), async (req, res) => {
    const { title, description, image } = req.body;

    try {
        const project = new Project({ title, description, image });
        await project.save();
        res.status(201).json(project);
    } catch (error) {
        res.status(500).json({ message: 'Error creating project', error });
    }
});

app.put('/api/projects/:id', auth, validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('description').notEmpty().withMessage('Description is required'),
]), async (req, res) => {
    const { title, description, image } = req.body;

    try {
        const project = await Project.findByIdAndUpdate(
            req.params.id,
            { title, description, image },
            { new: true }
        );
        if (!project) {
            return res.status(404).json({ message: 'Project not found' });
        }
        res.json(project);
    } catch (error) {
        res.status(500).json({ message: 'Error updating project', error });
    }
});

app.delete('/api/projects/:id', auth, async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);
        if (!project) {
            return res.status(404).json({ message: 'Project not found' });
        }
        res.json({ message: 'Project deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting project', error });
    }
});

// Testimonial Routes
app.get('/api/testimonials', async (req, res) => {
    try {
        const testimonials = await Testimonial.find().sort({ createdAt: -1 });
        res.json(testimonials);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching testimonials', error });
    }
});

app.post('/api/testimonials', auth, validate([
    body('content').notEmpty().withMessage('Content is required'),
    body('author').notEmpty().withMessage('Author is required'),
    body('role').notEmpty().withMessage('Role is required'),
]), async (req, res) => {
    const { content, author, role } = req.body;

    try {
        const testimonial = new Testimonial({ content, author, role });
        await testimonial.save();
        res.status(201).json(testimonial);
    } catch (error) {
        res.status(500).json({ message: 'Error creating testimonial', error });
    }
});

app.put('/api/testimonials/:id', auth, validate([
    body('content').notEmpty().withMessage('Content is required'),
    body('author').notEmpty().withMessage('Author is required'),
    body('role').notEmpty().withMessage('Role is required'),
]), async (req, res) => {
    const { content, author, role } = req.body;

    try {
        const testimonial = await Testimonial.findByIdAndUpdate(
            req.params.id,
            { content, author, role },
            { new: true }
        );
        if (!testimonial) {
            return res.status(404).json({ message: 'Testimonial not found' });
        }
        res.json(testimonial);
    } catch (error) {
        res.status(500).json({ message: 'Error updating testimonial', error });
    }
});

app.delete('/api/testimonials/:id', auth, async (req, res) => {
    try {
        const testimonial = await Testimonial.findByIdAndDelete(req.params.id);
        if (!testimonial) {
            return res.status(404).json({ message: 'Testimonial not found' });
        }
        res.json({ message: 'Testimonial deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting testimonial', error });
    }
});

// Certificate Routes
app.get('/api/certificates', async (req, res) => {
    try {
        const certificates = await Certificate.find().sort({ createdAt: -1 });
        res.json(certificates);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching certificates', error });
    }
});

app.post('/api/certificates', auth, validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('issuer').notEmpty().withMessage('Issuer is required'),
]), async (req, res) => {
    const { title, issuer, image } = req.body;

    try {
        const certificate = new Certificate({ title, issuer, image });
        await certificate.save();
        res.status(201).json(certificate);
    } catch (error) {
        res.status(500).json({ message: 'Error creating certificate', error });
    }
});

app.put('/api/certificates/:id', auth, validate([
    body('title').notEmpty().withMessage('Title is required'),
    body('issuer').notEmpty().withMessage('Issuer is required'),
]), async (req, res) => {
    const { title, issuer, image } = req.body;

    try {
        const certificate = await Certificate.findByIdAndUpdate(
            req.params.id,
            { title, issuer, image },
            { new: true }
        );
        if (!certificate) {
            return res.status(404).json({ message: 'Certificate not found' });
        }
        res.json(certificate);
    } catch (error) {
        res.status(500).json({ message: 'Error updating certificate', error });
    }
});

app.delete('/api/certificates/:id', auth, async (req, res) => {
    try {
        const certificate = await Certificate.findByIdAndDelete(req.params.id);
        if (!certificate) {
            return res.status(404).json({ message: 'Certificate not found' });
        }
        res.json({ message: 'Certificate deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting certificate', error });
    }
});

// Authentication Routes
app.post('/api/auth/register', validate([
    body('username').notEmpty().withMessage('Username is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
]), async (req, res) => {
    const { username, password } = req.body;

    try {
        let user = await User.findOne({ username });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        user = new User({ username, password });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        const payload = { user: { id: user.id } };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error });
    }
});

app.post('/api/auth/login', validate([
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
]), async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const payload = { user: { id: user.id } };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error });
    }
});

// Basic Route
app.get('/', (req, res) => {
    res.send('Cybersecurity Portfolio Backend');
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
