const mongoose = require("mongoose");

const BookSchema = new mongoose.Schema(
    {
        job: {
            type: mongoose.Schema.Types.ObjectId, ref: "Job",
        },
        userId: { type: String, required: true, },
        title: { type: String, required: true, },
        imageUrl: { type: String, required: true, },
        company: { type: String, required: true, },
        location: { type: String, required: true, },


    }, { timestamps: true }
);
module.exports = mongoose.model("Bookmark", BookSchema)