import dotenv from "dotenv";
import connectDB from './database/index.js';
import { app } from "./app.js";

dotenv.config({
    path: './.env'
})

connectDB()
    .then(() => {
        app.listen(process.env.PORT || 8000)
        console.log(`Server started on port ${process.env.PORT}`);
    })

    .catch((err) => {
        console.log("MONGO ERROR: " + err);
    })















/*
import express from 'express';
const app = express();

(async () => {
    try {
        await mongoose.connect(`${process.env.MONGODB_URL}/${DB_NAME}`)
        app.on("error", (error) => {
            console.log("Error:", error);
            throw error;
        })

        app.listen(process.env.PORT,()=>{
            console.log(`App listening on ${process.env.PORT}`);
        })


    } catch (error) {
        console.error("Error", error);
    }
})()*/