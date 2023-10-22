const express = require('express')
const router = express.Router()
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')

const User = require('../models/user'); // Your user model

function authenticateToken(req, res, next) {
    const authHeader = req.header('Authorization'); // Get the Authorization header

    // Check if the Authorization header is present and starts with 'Bearer '
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Access denied' });
    }

    // Extract the token from the Authorization header
    const token = authHeader.split(' ')[1];

    try {
        const verified = jwt.verify(token, 'secretsanta'); // Verify the token with your secret
        req.user = verified;
        next(); // Continue to the next middleware or route handler
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
}

router.get('/', authenticateToken, async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
})

// Registration endpoint
router.post('/register', async (req, res) => {
    try {
        // Check the total number of registered users
        const totalUsers = await User.countDocuments();
        if (totalUsers >= 15) {
            return res.status(400).json({ message: 'Registration is closed. Maximum participants reached.' });
        }

        const { name, codeName, password } = req.body;
        const isPaired = false; // New users are not initially paired

        // Check if the codeName is already in use
        const existingCodeName = await User.findOne({ codeName });
        if (existingCodeName) {
            return res.status(400).json({ message: 'Code name already in use. Please choose a different one.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user without the wishlists field
        const user = new User({ name, codeName, password: hashedPassword, isPaired });
        await user.save();

        // Create a JWT token
        const token = jwt.sign({ userId: user._id }, 'secretsanta');
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});


// Login endpoint
router.post('/login', async (req, res) => {
    try {
        const { codeName, password } = req.body;

        // Check if the codeName exists
        const user = await User.findOne({ codeName });
        if (!user) {
            return res.status(400).json({ message: 'Code Name not found' });
        }

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password. Please try again.' });
        }

        // Create a JWT token
        const token = jwt.sign({ userId: user._id }, 'secretsanta');

        // Include user details in the response
        const userResponse = {
            userId: user._id,
            name: user.name,
            codeName: user.codeName,
            // Add other user details you want to include here
        };

        res.json({ token, user: userResponse });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});


module.exports = router