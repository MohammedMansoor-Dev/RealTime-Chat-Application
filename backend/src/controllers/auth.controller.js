import cloudinary from "../lib/cloudinary.js"
import { generateToken } from "../lib/utils.js"
import User from "../models/user.model.js"
import bcrypt from 'bcryptjs'

export const signup = async (req, res) => {
    const { email, fullName, password } = req.body
    try {
        if (!fullName || !email || !password) return res.status(400).json({ message: 'All fields are required!!!' })

        if (password.length < 6) return res.status(400).json({ message: 'Password must be 6 characters long!!!' })

        const user = await User.findOne({ email })

        if (user) return res.status(400).json({ message: 'User already exists!!!' })

        const hashPassword = await bcrypt.hash(password, 10)

        const newUser = new User({
            fullName,
            email,
            password: hashPassword
        })

        if (newUser) {
            generateToken(newUser._id, res)
            await newUser.save()

            res.status(201).json({
                _id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                profilePic: newUser.profilePic
            })
        } else {
            res.status(400).json({
                message: 'Invalid User Data!!!'
            })
        }

    } catch (error) {
        return res.status(500).json({ message: 'Internal Server Error' })
    }
}

export const signin = async (req, res) => {
    const { email, password } = req.body
    try {
        const user = await User.findOne({ email })

        if (!user) return res.status(400).json({ message: 'Invalid Credentials!!!' })

        const isPasswordMatch = await bcrypt.compare(password, user.password)

        if (!isPasswordMatch) return res.status(400).json({ message: 'Invalid Credentials!!!' })

        generateToken(user._id, res)

        return res.status(200).json({
            _id: user._id,
            fullName: user.fullName,
            email: user.email,
            profilePic: user.profilePic
        })

    } catch (error) {
        return res.status(500).json({ message: 'Internal Server Error!!!' })
    }
}

export const logout = (req, res) => {
    try {
        res.cookie('token', '', { maxAge: 0 })
        return res.status(200).json({ message: 'Loggout Successfully' })
    } catch (error) {
        return res.status(500).json({ message: 'Internal Server Error!!!' })
    }
}

export const updateProfile = async (req, res) => {
    try {
        const { profilePic } = req.body
        const userId = req.user._id

        if (!profilePic) return res.status(400).json({ message: 'Profile Pic is required' })

        const uploadResponse = await cloudinary.uploader.upload(profilePic)

        const updatedUser = await User.findByIdAndUpdate(userId, { profilePic: uploadResponse.secure_url }, { new: true })

        res.status(200).json(updatedUser)
    } catch (error) {
        return res.status(500).json({ message: 'Internal Server Error!!!' })
    }
}

export const checkAuth = (req, res)=>{
    try {
        res.status(200).json(req.user)
    } catch (error) {
        return res.status(500).json({ message: 'Internal Server Error!!!' })
    }
}