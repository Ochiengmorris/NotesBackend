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
const jwtSecret = process.env.JWTSECRET || 'iodniwdjhcniwdjscnxedowkcnedwcknwdoc';
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
    methods: ['POST', 'GET'],
    origin: 'https://vercel-mern-frontend.vercel.app',
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
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        const userDoc = await User.findOne({ email: email });
        if (userDoc) {
            const passGood = await bcrypt.compare(password, userDoc.password);
            if (passGood) {
                jwt.sign({ email: userDoc.email, id: userDoc._id }, jwtSecret, { expiresIn: '24h' }, (err, token) => {
                    if (err) {
                        throw err;
                    }
                    // const isProduction = process.env.NODE_ENV === 'production';
                    res.cookie('token', token,
                        {
                            httpOnly: true,
                            secure: true,
                            sameSite: 'None',
                            maxAge: 24 * 60 * 60 * 1000
                        }).json(userDoc);
                });
            } else {
                res.status(422).json({ message: 'Invalid email or password!' });
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
            if (err) throw err;
            const { name, email, _id } = await User.findById(userData.id)
            res.json({ name, email, _id });
        })
    } else {
        res.json(null)
    }
});
app.post('/logout', (req, res) => {
    const isProduction = process.env.NODE_ENV === 'production';
    res.cookie('token', '', {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'None',
        maxAge: 0,
    }).json({ message: 'Logged out' });
});

app.post('/note', (req, res) => {
    const { owner, note } = req.body;
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, jwtSecret, {}, async (err, userData) => {
            try {
                await Note.create({
                    owner,
                    note,
                });
                res.status(200).json('note added succesfully');
            } catch (e) {
                res.status(422).json(e);
            }
        });
    } else {
        res.status(401).json('please login to add a note');
    }
})
app.post('/change-password', async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) return res.status(401).json({ message: 'Unauthorized' });

        try {
            const userDoc = await User.findById(userData.id);
            const passGood = await bcrypt.compare(currentPassword, userDoc.password);

            if (!passGood) {
                return res.status(403).json({ message: 'Current password is incorrect' });
            }

            userDoc.password = bcrypt.hashSync(newPassword, salt);
            await userDoc.save();

            res.json({ message: 'Password updated successfully' });
        } catch (error) {
            console.error('Error changing password:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    });
})

// Start Server
app.listen(PORT, () => {
    connect();
    console.log("connected to backend");
})
