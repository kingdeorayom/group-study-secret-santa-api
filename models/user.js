const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true,
        minlength: 2,
    },

    password: {
        type: String,
        required: true,
        minlength: 8,
    },

    codeName: {
        type: String,
        required: true,
        unique: true,
        minlength: 4,
    },

    isPicked: {
        type: Boolean,
        default: false,
    },

    hasPicked: {
        type: Boolean,
        default: false,
    },

    recipient: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    },

    wishlists: [
        {
            id: mongoose.Schema.Types.ObjectId,
            title: String,
            priority: String,
            links: [String],
        },
    ],

});

module.exports = mongoose.model('User', userSchema);
