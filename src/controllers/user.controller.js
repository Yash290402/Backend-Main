import { asynchandler } from '../utils/asynchandler.js';
import { APIerror } from '../utils/APIerror.js';
import { User } from '../models/user.model.js';
import { uploadOncloudinary } from '../utils/cloudinary.js';
import { APIResponse } from '../utils/APIResponse.js';
import jwt from 'jsonwebtoken';


const generateAccessTokenandrefereshToken = async (userId) => {
    try {

        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validatebeforeSave: false })

        return { accessToken, refreshToken }


    } catch (error) {
        throw new APIerror(500, "something went wrong while generating access token and refresh token")
    }
}




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
        throw new APIerror(400, "Avatar is required")
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



const loginUser = asynchandler(async (req, res) => {
    //req body -> data
    //username or email
    //find the user
    //password check
    //access token and refresh token
    //send cookies

    const { email, username, password } = req.body
    console.log(email);

    if (!(username || email)) {
        throw new APIerror(400, "username or password is required")
    }

    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new APIerror(404, "User does not exist");
    }

    const isPasswordvalid = await user.isPasswordCorrect(password)


    if (!isPasswordvalid) {
        throw new APIerror(401, "Passsword incorrect does not exist");
    }


    const { accessToken, refreshToken } = await
        generateAccessTokenandrefereshToken(user._id)

    const loggedInUser = await User.findById(user._id)
        .select("-password -refreshToken ")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new APIResponse(
                200,
                {
                    user: loggedInUser, accessToken,
                    refreshToken
                },
                "user logged in successfully"
            )
        )

})

const logoutUser = asynchandler(async (req, res) => {
    await User.findOneAndUpdate(
        { _id: req.user._id },
        {
            $set: {
                refreshToken: undefined,
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new APIResponse(200, {}, "user logged out"));
})

const refreshAccessToken = asynchandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new APIerror(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )

        const user = await User.findById(decodedToken?._id)

        if (!user) {
            throw new APIerror(401, "invalid refresh token")
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new APIerror(401, "Refresh token is expired or used")
        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newrefreshToken } = await generateAccessTokenandrefereshToken(user._id)


        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newrefreshToken, options)
            .json(
                new APIResponse(
                    200,
                    { accessToken, refreshToken: newrefreshToken },
                    "Access token refreshed"
                )
            )

    } catch (error) {
        throw new APIerror(401, error?.message || "invlaid refresh token")
    }
})

const changeCurrentPassword = asynchandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body

    // if(!(newPassword===confPassword)) {
    //     throw new APIerror(401, error?.message || "password mismatch")
    // }


    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new APIerror(400, "Invalid password")
    }

    user.password = newPassword
    user.save({ validatebeforeSave: false })

    return res
        .status(200)
        .json(new APIResponse(200, {}, "password changed successfully"))
})

const getCurrentUser = asynchandler(async (req, res) => {
    return res
        .status(200)
        .json(new APIResponse(200, req.user, "current user fetched successfully"))
})


const upadateAccountDetails = asynchandler(async (req, res) => {
    const { fullname, email } = req.body

    if (!fullname || !email) {
        throw new APIerror(400, "all fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullname: fullname,
                email: email
            }
        },
        { new: true }


    ).select("-password")

    return res
        .status(200)
        .json(new APIResponse(200, user, "Account updated"))
})

const upadteUserAvatar = asynchandler(async (req, res) => {
    const avatarlocalPath = req.file?.path

    if (!avatarlocalPath) {
        throw new APIerror(400, "Avatar file is missing")
    }

    const avatar = await uploadOncloudinary(avatarlocalPath)

    if (!avatar.url) {
        throw new APIerror(400, "error uploading avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        { new: true }
    ).select("-password")

    return res
        .status(200)
        .json(
            new APIResponse(200, user, "avatar image updated successfully")
        )
})


const upadteUserCoverImage = asynchandler(async (req, res) => {
    const coverImagePath = req.file?.path

    if (!coverImagePath) {
        throw new APIerror(400, "cover image file is missing")
    }

    const coverImage = await uploadOncloudinary(coverImagePath)

    if (!coverImagePath.url) {
        throw new APIerror(400, "error uploading avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        { new: true }
    ).select("-password")

    return res
        .status(200)
        .json(
            new APIResponse(200, user, "Cover image updated successfully")
        )
})


const getusercheannelprofile = asynchandler(async (req, res) => {
    const { username } = req.params

    if (!username?.trim()) {
        throw new APIerror(400, "username is missing")
    }

    const channel = await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "Subscription",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"

            }
        },
        {
            $lookup: {
                from: "Subscription",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscriberCount: {
                    $size: "subscribers"
                },

                channelssubscribedCount: {
                    $size: "subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: { $in: [req.user?._id, "subscribers"] },
                        then: true,
                        else: false
                    }
                }

            }
        },
        {
            $project: {
                fullname: 1,
                username: 1,
                subscriberCount: 1,
                channelssubscribedCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if (!channel?.length) {
        throw new APIerror(404, "channel does not exist")
    }

    return res
        .status(200)
        .json(
            new APIResponse(200, channel[0], "user channel fetched successfully")
        )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    upadateAccountDetails,
    upadteUserAvatar,
    upadteUserCoverImage,
    getusercheannelprofile

} 