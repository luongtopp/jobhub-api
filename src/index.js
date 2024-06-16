const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const dotenv = require('dotenv');

const authRoute = require("../routes/auth");
const userRoute = require("../routes/user");
const jobRoute = require("../routes/job");
const bookmarkRoute = require("../routes/bookmark");
const chatRoute = require("../routes/chat");
const messageRoute = require("../routes/messages");


dotenv.config()
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log("connected to the db")).catch((err) => { console.log(err) });



app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/api/", authRoute);
app.use("/api/users", userRoute);
app.use("/api/jobs", jobRoute);
app.use("/api/bookmarks", bookmarkRoute);
app.use("/api/chats", chatRoute);
app.use("/api/messages", messageRoute);


const server = app.listen(process.env.PORT || 4000, () => console.log(`Example app listening on port ${process.env.PORT}!`));

const io = require('socket.io')(server,
    {
        pingTimeout: 60000,
        cors: {
            // origin: "http:localhost:5001",
            origin: "https://jobhub-api-production.up.railway.app",

        },
    });

io.on("connection", (socket) => {
    console.log("connected to sockets");

    socket.on('setup', (userId) => {
        socket.join(userId);
        socket.broadcast.emit('online-users', userId)
        console.log(userId);

    });

    socket.on("typing", (room) => {
        console.log('typing');
        console.log(room);
        socket.to(room).emit("typing", room)
    });
    socket.on("stop typing", (room) => {
        console.log('stopped typing');
        console.log(room);
        socket.to(room).emit("stop typing", room)
    });

    socket.on('join chat', (room) => {
        socket.join(room);
        console.log('User Joined Room :' + room);
    });

    socket.on("new message", (newMessageReceived) => {

        var chat = newMessageReceived.chat;
        var room = chat._id;

        var sender = newMessageReceived.sender;
        var receiver = newMessageReceived.receiver;

        if (!sender || !sender._id) {
            console.log("Sender not defined or missing _id property");
            return;
        }

        var senderId = sender._id;
        console.log(senderId + "sender");
        const users = chat.users;

        if (!users) {
            console.log("Chat users not defined");
            return;
        }

        socket.to(room).emit("message received", newMessageReceived);
        socket.to(room).emit("message sent", "New Message");

    });

    socket.off("setup", () => {
        console.log("USER DISCONNECTED");
        socket.leave(userId);
    });
})