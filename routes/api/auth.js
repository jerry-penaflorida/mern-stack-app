const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const User = require('../../models/User');
const { check, validationResult } = require('express-validator');

// @route  GET api/auth
// @desc   Test route
// @access Public
router.get('/', auth, async(req, res) => {
    try {
        //We have access to req.user, because we set that value in the auth middleware
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route  POST api/auth
// @desc   Authenticate user and get token
// @access Public
router.post('/', 
[
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], 
async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try { 
        let user = await User.findOne({ email })

        if(!user) {
            return res
                .status(400)
                .json({ errors: [ { mesg: 'Invalid credentials' } ]
            });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch) {
            return res
                .status(400)
                .json({ errors: [ { mesg: 'Invalid credentials' } ]
            });
        }

        const payLoad = {
            user: {
                id: user.id
            }
        }

        jwt.sign(
            payLoad, 
            config.get('jwtSecret'),
            { expiresIn: 360000 },
            (err, token) => {
                if(err) throw err;
                res.json({ token })
            }
        );


    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;