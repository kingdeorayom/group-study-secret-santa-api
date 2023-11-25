const express = require('express')
const router = express.Router()
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const crypto = require('crypto');

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

// Get all users
router.get('/', authenticateToken, async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
})

// Get one user
router.get('/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;

        // Find a user by their ID
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Get wishlist items of a user
router.get('/:userId/wishlist', authenticateToken, async (req, res) => {

    const userId = req.params.userId;

    try {
        const user = await User.findById(userId).select('wishlists'); // Select only the 'wishlists' field
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user.wishlists); // Return the wishlists directly
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Create a new wishlist item for a user
router.post('/add-wishlist/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const { title, priority, description, links } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if title and priority are not empty
        if (!title || !priority) {
            return res.status(400).json({ message: 'Title, priority and description are required' });
        }

        const newWishlistItem = {
            title,
            description,
            priority,
            links,
        };

        user.wishlists.push(newWishlistItem);
        await user.save();

        // Get the added wishlist item with the generated _id
        const addedItem = user.wishlists[user.wishlists.length - 1];

        res.status(201).json({ message: 'Wishlist item added successfully', data: addedItem });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


// Delete a wishlist item for a user
router.delete('/delete-wishlist/:userId/:itemId', async (req, res) => {

    const userId = req.params.userId;
    const itemId = req.params.itemId;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const wishlistItemIndex = user.wishlists.findIndex((item) => item._id.toString() === itemId);

        if (wishlistItemIndex === -1) {
            return res.status(404).json({ message: 'Wishlist item not found' });
        }

        // Remove the wishlist item from the user's wishlists array
        user.wishlists.splice(wishlistItemIndex, 1);
        await user.save();

        res.status(200).json({ message: 'Wishlist item deleted successfully', deletedItemId: itemId });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


router.post('/pick/:userId', async (req, res) => {
    try {
        const pickerId = req.params.userId;
        // Find the participant who is picking
        const picker = await User.findById(pickerId);

        if (!picker || picker.hasPicked) {
            return res.status(400).json({ message: 'Invalid or already paired participant.' });
        }

        // Find all unpicked participants except the current picker
        const potentialRecipients = await User.find({ _id: { $ne: pickerId }, isPicked: false });

        if (potentialRecipients.length === 0) {
            return res.status(400).json({ message: 'No available participants to pick.' });
        }

        // Check if the last picker is about to pick
        if (potentialRecipients.length === 1) {
            // If there's only one unpicked participant left, assign that participant to the last picker
            const recipient = potentialRecipients[0];
            recipient.isPicked = true;
            await recipient.save();

            // Update the picker's information
            picker.hasPicked = true;
            picker.recipient = recipient._id;
            await picker.save();

            // Decrypt the real name when including it in the response
            const decryptedPickerName = decrypt(picker.name, 'encryptionKey');
            const decryptedRecipientName = decrypt(recipient.name, 'encryptionKey');

            res.json({
                message: `You've picked a participant: ${recipient.codeName}`,
                pickerDetails: {
                    userId: picker._id,
                    name: decryptedPickerName,
                    codeName: picker.codeName,
                    isPicked: picker.isPicked,
                    hasPicked: picker.hasPicked,
                    recipient: {
                        _id: recipient._id
                    }
                },
                recipientDetails: {
                    userId: recipient._id,
                    name: decryptedRecipientName,
                    codeName: recipient.codeName,
                    isPicked: recipient.isPicked,
                    hasPicked: recipient.hasPicked,
                    wishlists: recipient.wishlists
                }
            });

        } else {
            // If there are multiple unpicked participants, randomly select a recipient
            const recipient = potentialRecipients[Math.floor(Math.random() * potentialRecipients.length)];
            recipient.isPicked = true;
            await recipient.save();

            // Update the picker's information
            picker.hasPicked = true;
            picker.recipient = recipient._id;
            await picker.save();

            // Decrypt the real name when including it in the response
            const decryptedPickerName = decrypt(picker.name, 'encryptionKey');
            const decryptedRecipientName = decrypt(recipient.name, 'encryptionKey');

            res.json({
                message: `You've picked a participant: ${recipient.codeName}`,
                pickerDetails: {
                    userId: picker._id,
                    name: decryptedPickerName,
                    codeName: picker.codeName,
                    isPicked: picker.isPicked,
                    hasPicked: picker.hasPicked,
                    recipient: {
                        _id: recipient._id
                    }
                },
                recipientDetails: {
                    userId: recipient._id,
                    name: decryptedRecipientName,
                    codeName: recipient.codeName,
                    isPicked: recipient.isPicked,
                    hasPicked: recipient.hasPicked,
                    wishlists: recipient.wishlists
                }
            });

        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Picking participant failed.' });
    }
});

// Registration endpoint
router.post('/register', async (req, res) => {
    try {
        // Check the total number of registered users
        const totalUsers = await User.countDocuments();
        if (totalUsers >= 15) {
            return res.status(400).json({ message: 'Registration is closed. Maximum participants reached.' });
        }

        const { name, codeName, password } = req.body;
        const isPicked = false; // New users are not initially paired

        // Check if the codeName is already in use
        const existingCodeName = await User.findOne({ codeName }).populate('recipient', '_id'); // Add .populate('recipient');
        if (existingCodeName) {
            return res.status(400).json({ message: 'Code name already in use. Please choose a different one.' });
        }

        // Encrypt the real name before saving it to the database
        const encryptedName = encrypt(name, 'encryptionKey');

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user without the wishlists field
        const user = new User({ name: encryptedName, codeName, password: hashedPassword, isPicked });
        await user.save();

        // Create a JWT token
        const token = jwt.sign({ userId: user._id }, 'secretsanta');

        // Decrypt the real name when including it in the response
        const decryptedName = decrypt(encryptedName, 'encryptionKey');

        // Include user details in the response
        const userResponse = {
            userId: user._id,
            name: decryptedName,
            codeName: user.codeName,
            isPicked: user.isPicked,
            hasPicked: user.hasPicked,
            recipient: user.recipient
            // Add other user details you want to include here
        };

        res.json({ token, user: userResponse });
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
        const user = await User.findOne({ codeName }).populate('recipient', '_id'); // Add .populate('recipient')

        if (!user) {
            return res.status(400).json({ message: 'There is no participant with this code name in the database. Please try again.' });
        }

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid log in credentials. Please try again.' });
        }

        // Create a JWT token
        const token = jwt.sign({ userId: user._id }, 'secretsanta');

        // Decrypt the real name when including it in the response
        const decryptedName = decrypt(user.name, 'encryptionKey');

        // Include user details in the response
        const userResponse = {
            userId: user._id,
            name: decryptedName,
            codeName: user.codeName,
            isPicked: user.isPicked,
            hasPicked: user.hasPicked,
            recipient: user.recipient
            // Add other user details you want to include here
        };

        res.json({ token, user: userResponse });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Change Password endpoint
router.post('/change-password', authenticateToken, async (req, res) => {
    try {
        const { userId, currentPassword, newPassword, confirmPassword } = req.body;

        // Fetch the user from the database
        const user = await User.findById(userId);

        // Verify the current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);

        if (!isCurrentPasswordValid) {
            return res.status(401).json({ message: 'Current password is incorrect. Please try again.' });
        }

        // Check if the new password matches the confirm password
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'New password and confirm password do not match.' });
        }

        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the database
        user.password = hashedNewPassword;
        await user.save();

        res.json({ message: 'Password changed successfully.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reset Password endpoint
router.post('/reset-password', async (req, res) => {
    try {
        const { codeName, newPassword, confirmPassword } = req.body;

        // Fetch the user from the database
        const user = await User.findOne({ codeName: codeName });

        if (!user) {
            return res.status(400).json({ message: 'There is no participant with this code name in the database. Please try again.' });
        }

        // Check if the new password matches the confirm password
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'New password and confirm password do not match.' });
        }

        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the database
        user.password = hashedNewPassword;
        await user.save();

        res.json({ message: 'Password changed successfully.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Encryption function
const encrypt = (text, key) => {
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
};

// Decryption function
const decrypt = (encryptedText, key) => {
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
};


module.exports = router