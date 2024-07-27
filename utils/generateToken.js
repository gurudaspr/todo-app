import jwt from "jsonwebtoken";


const secret_key = process.env.JWT_SECRET;

export const generateToken = (user) => {
    return jwt.sign({ data: user._id }, secret_key, { 
      expiresIn: "1d" });
  };
