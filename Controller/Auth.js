const userSchema = require('../Model/Auth');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const Handlebars = require('handlebars');

const welcomeSource = fs.readFileSync(path.resolve(__dirname, '../Views/welcome.hbs'), 'utf8');
const welcomeTemplate = Handlebars.compile(welcomeSource);
const otpSource = fs.readFileSync(path.resolve(__dirname, '../Views/loginOtp.hbs'), 'utf8');
const otpTemplate = Handlebars.compile(otpSource);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASSWORD
    }
});

const signUp = async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;
        if (!email) return res.status(400).json({ status: 'error', message: 'Email required' });

        const userExist = await userSchema.findOne({ email: email });
        if (userExist) return res.status(400).json({ status: 'error', message: 'User already exists' });

        if (!password || !firstName || !lastName) {
            return res.status(400).json({ status: 'error', message: 'User credentials are required' });
        }

        // Hash the password using bcrypt
        // const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userSchema({
            email: email,
            password: password,
            firstName: firstName,
            lastName: lastName,
        });

        // Send welcome email
        const sendWelcomeEmail = async (user) => {
            try {
                const mailOptions = {
                    from: process.env.GMAIL_USER,
                    to: user.email,
                    subject: 'Welcome to Your App!',
                    html: welcomeTemplate({
                        email: user.email,
                        name: user.firstName + ' ' + user.lastName
                    }), // Pass user data to the template
                };

                const info = await transporter.sendMail(mailOptions);
                console.log('Welcome email sent:', info.response);
            } catch (error) {
                console.error('Error sending welcome email:', error);
                return res.status(400).json({ status: 'error', message: error.message });
            }
        };
        sendWelcomeEmail(user)

        await user.save();
        res.status(200).json({ status: 'success', message: 'User registered successfully' });
    } catch (err) {
        return res.status(400).json({ status: 'error', message: err.message });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) { return res.status(400).json({ status: 'error', message: 'User credentials are required' }); }
        const user = await userSchema.findOne({ email: email });
        if (user && await bcrypt.compare(password, user.password)) {
            const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
            const expiryTime = new Date(Date.now() + 60000); // OTP expiry time: 10 minutes

            await userSchema.findOneAndUpdate({ email }, {
                otp: {
                    code: otpCode,
                    expiry: expiryTime,
                },
            });

            const sendOtpEmail = async (user) => {
                try {
                    const mailOptions = {
                        from: process.env.GMAIL_USER,
                        to: user.email,
                        subject: 'OTP verification!',
                        html: otpTemplate({
                            email: user.email,
                            name: user.firstName + ' ' + user.lastName,
                            otp: otpCode
                        }), // Pass user data to the template
                    };

                    const info = await transporter.sendMail(mailOptions);
                } catch (error) {
                    return res.status(400).json({ status: 'error', message: error.message });
                }
            };
            sendOtpEmail(user)
            return res.status(200).json({status: 'success', data : "successfully send otp to the email"})
        }
        return res.status(400).json({ status: 'error', message: 'Error in User credentials' })
    }
    catch (err) {
        console.log(err)
        return res.status(400).json({ status: 'error', message: err.message })
    }
}


const verifyOtp = async (req, res, next) => {
    try {
        const { otp, email } = req.body;
        const user = await userSchema.findOne({ 'otp.code': otp });
        console.log(user)
        if (!user || user.otp.code !== otp) {
            return res.json({ status: 'error', message: 'Invalid OTP code' });
        }
        if (new Date() > new Date(user.otp.expiry)) {
            return res.json({ status: 'error', message: 'OTP expired' });
        }

        // Clear the OTP after successful verification
        await userSchema.findOneAndUpdate({ 'otp.code': otp }, {
            $unset: { otp: '' },
        });
        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
            },
            process.env.SECURE_KEY,
            {
                expiresIn: '1d',
            }
        );
        return res.status(200).json({ status: 'success', token: token });
    }
    catch (err) {
        console.log(err)
        return res.status(400).json({ status: 'error', err: err });
    }
}

module.exports = {
    signUp: signUp,
    login: login,
    verifyOtp: verifyOtp,
};
