const express = require("express");
const _router = express.Router();
const con = require("../db");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const dotenv = require("dotenv");

dotenv.config();

_router.post("/register", (req, res) => {
    let email = req.body.email;
    let password = req.body.password;

    con.query("SELECT * FROM users where email = ?", [email], (err, rows) => {
        if (!err)
            if(rows.length > 0) {
                // User exists
                res.send({
                    isRegistered: false,
                    msg: "User with the given email already exists"
                });
            } else {
                // User does not exists
                // Hash Password
                bcrypt.genSalt(10, (err, salt) => 
                    bcrypt.hash(password, salt, (err, hashPass) => {
                        // If there is an error while hasing the password
                        if(err) throw err;

                        // Else insert the new user into the database
                        con.query("INSERT INTO users (email, password) VALUES(?, ?)", [email, hashPass], (error, user) => {
                            if (!error) {
                                res.send({
                                    isRegistered: true,
                                    msg: "You are now registered and can login"
                                });
                            }
                            else {
                                res.send({ error: error });
                            }
                        });
                    })
                );
            }
        else
            res.send({ error: err });
    });
});

_router.post("/signin", (req, res) => {
    // console.log(req.body.role);
    if (req.body.role === "user") {
        con.query("SELECT * FROM users WHERE email = ?", [req.body.email], (err, rows) => {
            if (!err) {
                if (rows.length > 0) {
                    let user = rows[0];
                    // Match password
                    bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
                        if(err) throw err;
    
                        if(isMatch) {
                            let token = jwt.sign(
                                {
                                    user: user.email,
                                    role: "user"
                                },
                                process.env.JWT_SECRET_KEY, { expiresIn: "2h" }
                            );
                            res.send({ isLoggedIn: true, token: token });
                        } else
                            res.send({ isLoggedIn: false, msg: "Incorrect password" });
                    });
                } else
                    res.send({ isLoggedIn: false, msg: "User does not exists" });
            } else
                res.send({ error: err });
        });
    } else {
        con.query("SELECT * FROM admins WHERE email = ?", [req.body.email], (err, rows) => {
            if (!err) {
                if (rows.length > 0) {
                    // Match password
                    if (rows[0].password === req.body.password) {
                        let token = jwt.sign(
                            {
                                user: rows[0].email,
                                role: "admin"
                            },
                            process.env.JWT_SECRET_KEY, { expiresIn: "2h" }
                        );
                        res.send({ isLoggedIn: true, token: token });
                    } else
                        res.send({ isLoggedIn: false, msg: "Incorrect password" });
                } else
                    res.send({ isLoggedIn: false, msg: "User does not exists" });
            } else
                res.send({ error: err });
        });
    }
});

_router.post("/request-reset-password", (req, res) => {
    con.query("SELECT * FROM users WHERE email = ?", [req.body.email], (err, rows) => {
        if (!err) {
            if (rows.length > 0) {
                let user = rows[0];
                let resetToken = crypto.randomBytes(16).toString('hex');
                let createdAt = new Date();
                createdAt.setHours(createdAt.getHours() + 2);

                con.query("INSERT INTO forgotpassword (user_id, resettoken, created_at) VALUES(?, ?, ?)", [user.id, resetToken, createdAt], (err) => {
                    if (!err) {
                        con.query("DELETE FROM forgotpassword WHERE resettoken <> ?", [resetToken], (err) => {
                            if (!err) {
                                console.log("Prasad");
                                let transporter = nodemailer.createTransport({
                                    service: 'gmail',
                                    host: 'smtp.gmail.com',
                                    secure: false,
                                    port: 465,
                                    auth: {
                                      user: process.env.EMAIL_USER,
                                      pass: process.env.EMAIL_PASS
                                    },
                                    tls: {
                                        rejectUnauthorized: false
                                    }
                                });
                                let mailOptions = {
                                    to: user.email,
                                    from: process.env.EMAIL_USER,
                                    subject: "Password Reset Request",
                                    text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' + 'Please click on the following link, or paste this into your browser to complete the process:\n\n' + 'http://localhost:4200/response-reset-password/' + resetToken + '\n\n' + 'If you did not request this, please ignore this email and your password will remain unchanged.\n'
                                }
                                transporter.sendMail(mailOptions, (err) => {
                                    if (err) console.log(err);
                                    else {
                                        res.send({
                                            isUserExist: true,
                                            msg: "Password reset link has been sent to your registerd emai. Please check and follow the instructions"
                                        });
                                    }
                                });
                            } else
                                res.send({ error: err });
                        });
                    } else
                        res.send({ error: err });
                });
            } else
                res.send({ isUserExist: false, msg: "Email does not exists" });
        } else
            res.send({ error: err });
    });
});

_router.post("/valid-password-token", (req, res) => {
    con.query("SELECT * FROM forgotpassword WHERE resettoken = ?", [req.body.resetToken], (err, rows) => {
        if (!err) {
            if (rows.length > 0) {
                let resetToken = rows[0];
                con.query("SELECT * FROM users WHERE id = ?", [resetToken.user_id], (err) => {
                    if (!err) {
                        res.send({ success: true, msg: "Token verified successfully" });
                    } else
                        res.send({ error: err });
                });
            } else
                res.send({ success: false, msg: "Invalid URL" });
        } else
            res.send({ error: err });
    });
});

_router.post("/new-password", (req, res) => {
    con.query("SELECT * FROM forgotpassword WHERE resettoken = ?", [req.body.resetToken], (err, rows) => {
        if (!err) {
            if (rows.length > 0) {
                let dt = new Date();
                if (rows[0].created_at < dt) {
                    res.send({ success: false, msg: "Token has expired, Please try again" });
                } else {
                    let resetToken = rows[0];
                    con.query("SELECT * FROM users WHERE id = ?", [resetToken.user_id], (err, rows) => {
                        if (!err) {
                            if (rows.length > 0) {
                                let user = rows[0];
                                // Hash new password
                                bcrypt.genSalt(10, (err, salt) => 
                                    bcrypt.hash(req.body.newPassword, salt, (err, hashPass) => {
                                        // If there is an error while hasing the password
                                        if(err) throw err;
                                        // Else update new password
                                        con.query("UPDATE users SET password = ? WHERE id = ?", [hashPass, user.id], (err) => {
                                            if (!err) {
                                                con.query("DELETE FROM forgotpassword WHERE resettoken = ?", [resetToken.resettoken], (err) => {
                                                    if (!err) {
                                                        res.send({
                                                            success: true,
                                                            msg: "Password reset successfully"
                                                        });
                                                    } else {
                                                        res.send({ error: err });
                                                    }
                                                });
                                            }
                                            else {
                                                res.send({ error: err });
                                            }
                                        });
                                    })
                                );
                            } else {
                                res.send({ success: false, msg: "User does not exist." });
                            }
                        } else
                            res.send({ error: err });
                    });
                }
            } else
                res.send({ success: false, msg: "Invalid reset token" });
        } else
            res.send({ error: err });
    });
});

module.exports = _router;