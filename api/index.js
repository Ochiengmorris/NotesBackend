const mongoose = require("mongoose");
const express = require('express');
const cors = require('cors');
const dotenv = require("dotenv");
dotenv.config();

const User = require('./models/UserModel.js');
const Note = require('./models/NotesModel.js');

const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');

const app = express();
const salt = bcrypt.genSaltSync(10);
const jwtSecret = 'iodniwdjhcniwdjscnxedowkcnedwcknwdoc';
const jwtExpiresIn = '1h';
const PORT = process.env.PORT || 8001;
const MONGO = process.env.MONGO

const connect = async () => {
    try {
        await mongoose.connect(MONGO);
        console.log("MONGODB connected!");
    } catch (error) {
        throw error
    }
};


app.use(express.json());
app.use(cookieParser());
app.use(cors({
    credentials: true,
    origin: ['https://vercel-mern-frontend.vercel.app'],
}));

// Routes
app.get('/', async (req, res) => {
    try {
        const AllNotes = await Note.find().populate('owner', 'name');
        // console.log(AllNotes);
        res.json(AllNotes);
    } catch (error) {
        console.error('Error retrieving places:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const userDoc = await User.create({
            name,
            email,
            password: bcrypt.hashSync(password, salt),
        });
        res.status(200).json(userDoc);
    } catch (e) {
        res.status(422).json(e);
    }

});
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const userDoc = await User.findOne({ email });
        if (userDoc) {
            const passGood = await bcrypt.compare(password, userDoc.password);
            if (passGood) {
                jwt.sign({ email: userDoc.email, id: userDoc._id }, jwtSecret, { expiresIn: jwtExpiresIn }, (err, token) => {
                    if (err) {
                        console.error('Error generating token:', err);
                        return res.status(500).json({ message: 'Error generating token' });
                    }
                    res.cookie('token', token, { httpOnly: true }).json(userDoc);
                });
            } else {
                res.status(401).json({ message: 'Wrong password!' });
            }
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.get('/profile', (req, res) => {
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, jwtSecret, {}, async (err, userData) => {
            if (err) {
                console.error('Token verification failed:', err);
                return res.status(401).json({ message: 'Invalid token' });
            }
            try {
                const { name, email, _id } = await User.findById(userData.id);
                res.json({ name, email, _id });
            } catch (error) {
                console.error('Error retrieving user:', error);
                res.status(500).json({ message: 'Error retrieving user' });
            }
        })
    } else {
        res.json(null)
    }
});

app.post('/note', (req, res) => {
    const { owner, note } = req.body;
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, jwtSecret, {}, async (err, userData) => {
            if (err) {
                console.error('Token verification failed:', err);
                return res.status(401).json({ message: 'Invalid token' });
            }
            try {
                await Note.create({
                    owner,
                    note,
                });
                res.status(201).json('Note added succesfully');
            } catch (e) {
                console.error('Error adding note:', e);
                res.status(422).json(e);
            }
        });
    } else {
        res.status(401).json('Access denied!', token);
    }
})
app.post('/logout', (req, res) => {
    res.cookie('token', '', { httpOnly: true }).json({ message: 'Logged out' });
});

// Start Server
app.listen(PORT, () => {
    connect();
    console.log("connected to backend");
})
