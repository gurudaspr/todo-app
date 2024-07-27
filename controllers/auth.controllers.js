import * as argon2 from "argon2";
import { PrismaClient } from "@prisma/client";
import { generateToken } from "../utils/generateToken.js";
const prisma = new PrismaClient();



export const signup = async (req, res) => {
    const { name, email, password, confirmPassword } = req.body
    try {
        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({ message: "Please fill all the fields" })
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" })
        }

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: "User with this email already exists" });
        }

        // Hash password
        const hashedPassword = await argon2.hash(password);
        const user = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword,
            }
        })
        res.status(201).json({ message: "User created successfully" })
    }
    catch (error) {
        console.log(error, "error while registering user")
        return res.status(500).json({ message: "Internal server error" })

    }
}

export const login = async (req, res) => {
    const { email, password } = req.body
    try {
        const user = await prisma.user.findUnique({ where: { email } })
        if (!user) {
            return res.status(400).json({ message: "User not found" })
        }
        if (!password) {
            return res.status(400).json({ message: "Password is required" })
        }
        const isPasswordCorrect = await argon2.verify(user.password , password)
        if (!isPasswordCorrect) {
            return res.status(400).json({ message: "Incorrect password" })
        }
        const token = generateToken(user)
        res.status(200).json({ message: "Login successful", token })
    }
    catch (error) {
        console.log(error, "error while logging in")
        return res.status(500).json({ message: "Internal server error" })
    }
}