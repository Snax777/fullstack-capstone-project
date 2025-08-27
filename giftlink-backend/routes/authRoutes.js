const express = require('express');
const router = express.Router();
const app = express();
const dotenv = require('dotenv');
const pino = require('pino');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const logger = pino();

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`
        const db = await connectToDatabase();

        // Task 2: Access MongoDB collection
        const collection = db.collection('users');

        //Task 3: Check for existing email
        const existingEmail = await collection.findOne({email: req.body.email});

        if (existingEmail) {
            logger.error('Email already exists');

            return res.status(404).json({error: 'Email already exists'});
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email = req.body.email;

        //Task 4: Save user details in database
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });
         //Task 5: Create JWT authentication with user._id as payload
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        const authtoken = jwt.sign(payload, JWT_SECRET);

        logger.info('User registered successfully');
        res.json({authtoken,email});
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();
        // Task 2: Access MongoDB `users` collection
        const collection = db.collection('users');
        // Task 3: Check for user credentials in database
        const theUser = await collection.findOne({email: req.body.email});
        // Task 4: Task 4: Check if the password matches the encrypyted password and send appropriate message on mismatch
        if (theUser) {
            const result = await bcryptjs.compare(req.body.password, theUser.password);

            if (!result) {
                logger.error('Password does not match');

                return res.status(404).json({error: 'Wrong password'});
            }
            
            // Task 5: Fetch user details from database
            const userName = theUser.firstName;
            const userEmail = theUser.email;
            // Task 6: Create JWT authentication if passwords match with user._id as payload
            let payload = {
                user: {id: theUser._id.toString()},
            }

            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User logged in successfully');
            res.json({authtoken, userName, userEmail });
        } else {
            logger.error('User does not exist');

            return res.status(404).json({error: 'User does not exist'});
        }
    } catch (e) {
         return res.status(500).send('Internal server error');

    }
});

router.put('/update', async (req, res) => {
    try {
        const errors = validationResult(req);
        const email = req.headers.email;

        if (!errors.isEmpty()) {
            logger.error('Validation error(s) in update request', errors.array());

            return res.status(404).json({errors: errors.array()});
        }

        if (!email) {
            logger.error('Email not found in request headers');

            return res.status(404).json({error: 'Email not found in request headers'});
        }

        const db = await connectToDatabase();
        const collection = db.collection('users');
        const existingUser = await collection.findOne({email: email});

        if (!existingUser) {
            logger.error('User does not exist');

            return res.status(404).json({error: 'User does not exist'});
        }

        existingUser.firstName = req.body.name;
        existingUser.updatedAt = new Date();

        const updateUserdetails = await collection.findOneAndUpdate(
            {email},
            {$set: existingUser},
            {returnDocument: 'after'}
        );
        const payload = {
            user: {id: existingUser._id.toString()},
        }
        const authtoken = jwt.sign(payload, JWT_SECRET);

        logger.info('User details successfully updated');
        res.json({authtoken});
    } catch (e) {
        return res.status(500).send('Internal Server Error');
    }
})

module.exports = router;