import { asynchandler } from '../utils/asynchandler.js';
import { APIerror } from '../utils/APIerror.js';
import { User } from '../models/user.model.js';
import { uploadOncloudinary } from '../utils/cloudinary.js';
import { APIResponse } from '../utils/APIResponse.js';


const registerUser = asynchandler(async (req, res) => {

    // get user details from frontend
    //validation -not empty
    //check if user already exists:username,email
    //check for images ,check for avatar
    //upload them to cloudinary,avatar
    //create user object-create entry in db
    //remove password and referesh token field from response
    //check for user creation
    //return response


    const { username, email, fullname, password } = req.body
    // console.log("email: ", email);

    if (
        [fullname, password, email, username].some((field) => field?.trim() === "")
    ) {
        throw new APIerror(400, "ALL fields are required")

    }
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new APIerror(409, "User with email or username already exists")
    }

    const avatarlocalPath = req.files?.avatar[0]?.path;

    let coverImagePath;

    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImagePath = req.files.coverImage[0].path
    }
    


    if (!avatarlocalPath) {

        throw new APIerror(400, "Avatar file is required1")

    }

    const avatar = await uploadOncloudinary(avatarlocalPath)
    const coverImage = await uploadOncloudinary(coverImagePath)


    if (!avatar) {
        throw new APIerror(400, "Avatar file is required")
    }

    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createUser) {
        throw new APIerror(500, "Something went wrong while registering")
    }

    return res.status(201).json(
        new APIResponse(200, createUser, "User registration successful")
    )
})


export { registerUser, } 