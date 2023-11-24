import dotenv from "dotenv";
import connectDB from './database/index.js';

dotenv.config({
    path: './.env'
})

connectDB()















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