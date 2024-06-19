const { User } = require('../models/User');
const crypto = require('crypto');
const { sanitizeUser } = require('../services/common');

const jwt = require('jsonwebtoken');
exports.createUser = async (req, res) => {
  try {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      'sha256',
      async (err, derivedKey) => {
        if (err) {
          return res.status(400).json({ error: 'Password hashing failed', details: err });
        }
          
        const hashedPassword = derivedKey.toString('hex');
        const user = new User({ ...req.body, password: hashedPassword, salt });

        try {
          const doc = await user.save();
          req.login(sanitizeUser(doc), (loginErr) => {
            if (loginErr) {
              return res.status(400).json({ error: 'Login failed', details: loginErr });
            }

            const token = jwt.sign(sanitizeUser(doc), process.env.JWT_SECRET_KEY);
            console.log(token);
            console.log("bha")
            res
              .cookie('jwt', token, {
                expires: new Date(Date.now() + 3600000),
                httpOnly: true,
              })
              .status(201)
              .json(token);
          });
        } catch (saveErr) {
          res.status(400).json({ error: 'User creation failed', details: saveErr });
        }
      }
    );
  } catch (err) {
    res.status(400).json({ error: 'Unexpected error', details: err });
  }
};

exports.loginUser = async (req, res) => {
  const user = req.user
  res
  .cookie('jwt', user.token, {
    expires: new Date(Date.now() + 3600000),
    httpOnly: true,
  })
  .status(201)
  .json({id:user.id, role:user.role});
};

exports.checkUser = async (req, res) => {
  console.log(req.user);
  res.json({ status: 'success', user: req.user });
};