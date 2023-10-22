const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    // email: {
    //     type: String,
    //     required: true,
    //     unique: true,
    //     lowercase: true,
    // },
    password: {
        type: String,
        required: true,
    },
    codeName: {
        type: String,
        required: true,
        unique: true,
    },
    isPaired: {
        type: Boolean,
        default: false, // Default value is false, indicating the user is not initially paired.
    },
    wishlists: [
        {
            item: String,
            priority: Number,
            // You can add more fields to the wishlist item as needed.
        },
    ],
});

module.exports = mongoose.model('User', userSchema)