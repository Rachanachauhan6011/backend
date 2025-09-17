import { Router } from "express";
import {logoutUser, registerUser, UserLogin} from "../controllers/user.controllers.js"
import { upload } from "../middlewares/multer.middlerwares.js";
import { verifyJWT } from "../middlewares/auth.middlerwares.js";

const router = Router()

router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser)
router.route("/login").post(UserLogin)
4//secured routes

router.route("/logout").post(verifyJWT, logoutUser)
router.route("/refresh-token").post(refreshAccessToken)

export default router