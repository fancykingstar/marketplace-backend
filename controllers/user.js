const jwt = require("jsonwebtoken");
const validator = require("validator");
const keys = require("../configs/keys");
const logger = require("../configs/logger");
const nodeMailer = require("../helpers/nodemailer");

const { resetPasswordEmail } = require("../helpers/htmlMails/reset-password");

// Load models
const User = require("../models/User");

const domain_regex = new RegExp("(?<=@)[^.]+.*$");

// @route POST api/users/login
// @desc Login user / Returning JWT token
// @access Public
exports.postLogin = async (req, res) => {
    const { email, password } = req.body;

    console.log(validator.isEmpty(password, { ignore_whitespace: true }));

    if (!password || !email) {
        return res.status(422).json({
            error: "All fields are required",
        });
    }

    if (!validator.isEmail(email)) {
        return res.status(422).json({
            error: "Invalid Email",
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(422).json({ email: "User does not exists" });
        }

        const matched = await user.hasSamePassword(password);
        if (!matched) {
            return res.status(422).json({
                error: "Wrong password",
            });
        }

        jwt.sign(
            {
                userId: user.id,
                role: user.role,
                email: user.email,
                username: user.firstName + " " + user.lastName,
            },
            keys.secretOrKey,
            { expiresIn: "30d" },
            (err, token) => {
                res.json({
                    success: true,
                    _token: token,
                    token: "Bearer " + token,
                    user: {
                        email: user.email,
                        firstName: user.firstName,
                        lastName: user.lastName,
                    },
                });
            }
        );
    } catch (error) {
        logger.error(error);
        return res.status(422).json({
            error: "Server occurred an error,  please try again",
        });
    }
};

exports.googleLogin = async (req, res) => {
    const email = req.body.email;
    const firstName = req.body.familyName;
    const lastName = req.body.givenName;

    // Find user by email
    User.findOne({ email }).then((user) => {
        // Check if user exists
        Promise.resolve()
            .then((_) => {
                if (!user) {
                    const newUser = new User({
                        firstName,
                        lastName,
                        email,
                        password: "default",
                    });

                    return newUser.save();
                } else {
                    return user;
                }
            })
            .then((user) => {
                const payload = {
                    userId: user.id,
                    role: "saler",
                    username: user.firstName + " " + user.lastName,
                    email: user.email,
                };

                // Sign token
                jwt.sign(
                    payload,
                    keys.secretOrKey,
                    {
                        expiresIn: 31556926, // 1 year in seconds
                    },
                    (err, token) => {
                        res.json({
                            success: true,
                            _token: token,
                            token: "Bearer " + token,
                            user: {
                                email: user.email,
                                firstName: user.firstName,
                                lastName: user.lastName,
                            },
                        });
                    }
                );
            })
            .catch((err) => {
                return res.status(400).json({ error: err });
            });
    });
};

exports.facebookLogin = async (req, res) => {
    const email = req.body.email;
    const firstName = req.body.first_name;
    const lastName = req.body.last_name;

    // Find user by email
    User.findOne({ email }).then((user) => {
        // Check if user exists
        Promise.resolve()
            .then((_) => {
                if (!user) {
                    const newUser = new User({
                        firstName,
                        lastName,
                        email,
                        password: "default",
                    });

                    return newUser.save();
                } else {
                    return user;
                }
            })
            .then((user) => {
                const payload = {
                    userId: user.id,
                    role: "saler",
                    username: user.firstName + " " + user.lastName,
                    email: user.email,
                };

                // Sign token
                jwt.sign(
                    payload,
                    keys.secretOrKey,
                    {
                        expiresIn: 31556926, // 1 year in seconds
                    },
                    (err, token) => {
                        res.json({
                            success: true,
                            _token: token,
                            token: "Bearer " + token,
                            user: {
                                email: user.email,
                                firstName: user.firstName,
                                lastName: user.lastName,
                            },
                        });
                    }
                );
            })
            .catch((err) => {
                return res.status(400).json({ error: err });
            });
    });
};

// @route POST api/users/register/user
// @desc Add new user
// @access Private
exports.postRegister = async (req, res) => {
    const { firstName, lastName, email, role, password } = req.body;

    if (!password || !email || !firstName || !lastName) {
        return res.status(422).json({
            error: "All fields are required",
        });
    }

    if (!validator.isEmail(email)) {
        return res.status(422).json({
            error: "Invalid Email",
        });
    }

    if (password.length < 6) {
        return res.status(422).json({
            error: "Password must be at least 6 characters",
        });
    }
    // const header = req.headers['authorization'];
    // if (typeof header !== 'undefined') {
    //   const bearer = header.split(' ');
    //   const token = bearer[1];
    //   jwt.verify(token, keys.secretOrKey, function (err, decoded) {
    //     if (err) {
    //       return res.status(403).json({
    //         error: 'Token is invalid and expired'
    //       });
    //     }
    //   });
    // } else {
    //   return res.status(403).json({
    //     alert: {
    //       title: 'Error!',
    //       detail: 'Authorization token not found'
    //     }
    //   });
    // }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(422).json({
                error: "User already exists",
            });
        }

        const user = await new User({
            firstName,
            lastName,
            email,
            role,
            password,
        }).save();

        return res.status(200).json({
            success: "User successfully registered",
        });
    } catch (error) {
        console.error(error);
        console.log(error);
        return res.status(422).json({
            error: "Server Error: Please try again",
        });
    }
};

// @route POST api/users/reset-password
// @desc Reset password
// @access Public
exports.postResetPassword = async (req, res) => {
    const { email } = req.body;

    if (!validator.isEmail(email)) {
        return res.status(422).json({
            error: "Invalid Email",
        });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(422).json({ email: "User does not exists" });
        }

        const token = jwt.sign(
            {
                userId: user._id,
                email,
            },
            keys.secretOrKey,
            { expiresIn: "1h" }
        );

        user.confirmToken = token;
        await user.save();

        const mailOptions = {
            //from: '"iAuto" <iauto.iradardata@gmail.com>', // sender address
            from: "fancykingstar2019@gmail.com",
            to: email, // list of receivers
            subject: "Password Reset", // Subject line
            html: resetPasswordEmail("localhost:3000", token), // html body
        };

        nodeMailer(mailOptions, process.env.FROM_EMAIL, process.env.FROM_EMAIL.PASSWORD)
            .then(() => {
                res.json({
                    success: "We've sent an email to reset password",
                });
            })
            .catch((error) => {
                console.log("ERROR ==> ");
                console.log(error);
                res.status(422).json({
                    error: "We've not sent an email to reset password",
                });
            });
    } catch (error) {
        logger.error(error);
        return res.status(422).json({
            error: "Server occurred an error,  please try again",
        });
    }
};

// @route   PUT api/users/reset-password
// @desc    Reset password
// @access  Public
exports.putResetPassword = async (req, res) => {
    const { passwordCurrent, password } = req.body;
    const { confirmToken } = req.body;
    console.log(confirmToken);
    try {
        const header = req.headers["authorization"];
        if (confirmToken !== undefined) {
            jwt.verify(confirmToken, keys.secretOrKey, function (err, decoded) {
                if (err) {
                    return res.status(403).json({
                        error: "Token is invalid and expired",
                    });
                }
                tokenUserId = decoded.userId.toString();
            });
            const user = await User.findById(tokenUserId);
            const matched = await user.hasSameConfirmToken(confirmToken);
            if (matched) {
                if (password.length < 6) {
                    return res.status(422).json({
                        error: "Password must be at least 6 characters",
                    });
                }

                user.password = password;
                delete user.confirmToken;
                await user.save();
            }
            return res.json({
                success: "Password has been reset",
            });
        } else if (typeof header !== "undefined") {
            const bearer = header.split(" ");
            const token = bearer[1];
            jwt.verify(token, keys.secretOrKey, function (err, decoded) {
                if (err) {
                    return res.status(403).json({
                        error: "Token is invalid and expired",
                    });
                }
                tokenUserId = decoded.userId.toString();
            });

            const user = await User.findById(tokenUserId);
            const matched = await user.hasSamePassword(passwordCurrent);
            if (matched) {
                if (password.length < 6) {
                    return res.status(422).json({
                        error: "Password must be at least 6 characters",
                    });
                }

                console.log("password", password);
                user.password = password;
                await user.save();
            }
            return res.json({
                success: "Password has been reset",
            });
        } else {
            return res.status(403).json({
                error: "Authorization token not found",
            });
        }
    } catch (error) {
        logger.error(error);
        return res.status(422).json({
            eror: "Server occurred an error,  please try again",
        });
    }
};
