import { APIerror } from "../utils/APIerror.js";
import { asynchandler } from "../utils/asynchandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

export const verifyJWT = asynchandler(async (req,res, next) => {
    try {
        const token = req.cookies.accessToken || req.header("Authorization")?.replace("Bearer ", "")
    
        if (!token) {
            throw new APIerror(401, "unauthorized request")
        }
    
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    
        console.log('Decoded Token:', decodedToken);
       
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
        console.log('User Object:', user);
    
        if(!user) {
            throw new APIerror(401, "invalid access token")
        }
    
        req.user = user;
        next()
    } catch (error) {
        throw new APIerror(401,error?.message ||"Invlaid access tokenF")
    }
})

