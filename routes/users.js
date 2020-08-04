const express = require("express");
const passport = require("passport");

const router = express.Router();

const userController = require("../controllers/user");

// @route POST api/users/login
// @desc Login user / Returning JWT token
// @access Public
router.post("/login", userController.postLogin);

// auth with google
router.post("/login/google", userController.googleLogin);

// auth with google
router.post("/login/facebook", userController.facebookLogin);

// @route POST api/users/adduser
// @desc Add new user
// @access Private
router.post("/register", userController.postRegister);

// @route POST api/users/reset-password
// @desc Reset user password
// @access Public
router.post("/forgot-password", userController.postResetPassword);

// @route   PUT api/users/reset-password
// @desc    Reset password
// @access  Public
router.put("/reset-password", userController.putResetPassword);

module.exports = router;
