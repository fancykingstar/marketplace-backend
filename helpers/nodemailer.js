const nodemailer = require("nodemailer");

const nodeMailer = async (mailOptions, authEmail, authPassword) => {
    // create reusable transporter object using the default SMTP transport
    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true, // true for 465, false for other ports
        auth: {
            user: authEmail,
            pass: authPassword,
        },
    });

    // send mail with defined transport object
    await transporter.sendMail(mailOptions);
};

module.exports = nodeMailer;
