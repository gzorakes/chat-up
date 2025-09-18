import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    // get token from cookies with package cookie-parser
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized, No token provided" });
    }
    // verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized, Invalid token" });
    }

    // get user from token
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // attach user to request object
    req.user = user;
    next();
  } catch (error) {
    console.log("Error in auth middleware:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
