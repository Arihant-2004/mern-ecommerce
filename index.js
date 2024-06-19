require('dotenv').config();
const {createProduct} =require('./controller/Product')
const express =require('express');
const mongoose=require('mongoose');
const productsRouter = require('./routes/Products');
const categoriesRouter = require('./routes/Category');
const brandsRouter = require('./routes/Brand');
const server =express();
const usersRouter = require('./routes/User');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');
const cors = require('cors')
const session = require('express-session');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const { User } = require('./models/User');
const { isAuth, sanitizeUser , cookieExtractor} = require('./services/common');
const path = require('path');

// JWT options
const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = process.env.JWT_SECRET_KEY; // TODO: should not be in code;
//middlewares
server.use(express.static(path.resolve(__dirname,'build')))
server.use(cookieParser());
server.use(
    session({
      secret: process.env.SESSION_KEY,
      resave: false, // don't save session if unmodified
      saveUninitialized: false, // don't create session until something stored
    })
  );
server.use(passport.authenticate('session'));
server.use(
  cors({
    exposedHeaders: ['X-Total-Count'],
  })
);
server.use(express.json()); 
main().catch(err=> console.log(err));
server.use('/products', isAuth(), productsRouter.router);
// we can also use JWT token for client-only auth
server.use('/category', isAuth(), categoriesRouter.router);
server.use('/brand', isAuth(), brandsRouter.router);
server.use('/users', isAuth(), usersRouter.router);
server.use('/auth', authRouter.router);
server.use('/cart', isAuth(), cartRouter.router);
server.use('/orders', isAuth(), ordersRouter.router);
passport.use(
  'local',
  new LocalStrategy(
    { usernameField: 'email' },
    async function (email, password, done) {
      try {
        const user = await User.findOne({ email: email });
        console.log(email, password, user);
        if (!user) {
          return done(null, false, { message: 'Invalid credentials' });
        }

        crypto.pbkdf2(password, user.salt, 310000, 32, 'sha256', async function (err, derivedKey) {
          if (err) {
            return done(err);
          }

          console.log("as");
          console.log(user.password);
          console.log(derivedKey.toString('hex'));

          const userPassBuff = Buffer.from(user.password, 'hex');
          const hashedpassBuff = Buffer.from(derivedKey);

          // Ensure lengths are equal before using timingSafeEqual
          if (
            userPassBuff.length !== hashedpassBuff.length ||
            !crypto.timingSafeEqual(userPassBuff, hashedpassBuff)
          ) {
            return done(null, false, { message: 'Invalid credentials' });
          }

          const token = jwt.sign(sanitizeUser(user), process.env.JWT_SECRET_KEY);
          done(null, { id:user.id,role:user.role,token }); // this lines sends to serializer
        });
      } catch (err) {
        done(err);
      }
    }
  )
);

  passport.use(
    'jwt',
    new JwtStrategy(opts, async function (jwt_payload, done) {
      console.log({ jwt_payload});
      console.log("Arihant");
      try {
        const user = await User.findById(jwt_payload.id);
        console.log(user);
        console.log("bhavesh");
        if (user) {
          return done(null, sanitizeUser(user)); // this calls serializer
        } else {
          return done(null, false);
        }
      } catch (err) {
        return done(err, false);
      }
    })
  );
passport.serializeUser(function (user, cb) {
    console.log('serialize', user);
    process.nextTick(function () {
      return cb(null, { id: user.id, role: user.role });
    });
  });
  passport.deserializeUser(function (user, cb) {
    console.log('de-serialize', user);
    process.nextTick(function () {
      return cb(null, user);
    });
  });
  
const app = express();
// This is a public sample test API key.
// Don’t submit any personally identifiable information in requests made with this key.
// Sign in to see your own test API key embedded in code samples.
const stripe = require("stripe")(process.env.STRIPE_KEY);

// Assuming you are 
server.post("/create-payment-intent", async (req, res) => {
  const {totalamount} = req.body;
  // Validate totalAmount to ensure it's a number and greater than 0
  if (isNaN(totalamount) || totalamount <= 0) {
    return res.status(400).send({ error: 'Invalid total amount' });
  }

  try {
    // Create a PaymentIntent with the order amount and currency
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(totalamount * 100), // Ensure amount is an integer
      currency: "inr",
      automatic_payment_methods: {
        enabled: true,
      },
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error('Error creating PaymentIntent:', error);
    res.status(500).send({ error: error.message });
  }
});
async function main(){
  try{
        await mongoose.connect(process.env.MONGODB_URL);
        console.log('database connected')
        console.log(process.env.MONGODB_URL)
  }catch(err){
    console.log(err);
  }
    }
server.get('/',(req,res)=>{
        res.json({status:'sucess'})
})
server.listen(process.env.PORT,()=>{
            console.log("hi arihant")
})

    