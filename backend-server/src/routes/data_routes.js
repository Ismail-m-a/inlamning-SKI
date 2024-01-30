// backend.js

const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit'); // Lägg till rate limiting
const helmet = require('helmet'); // Lägg till Helmet för att hantera HTTP-säkerhet

require('dotenv').config();

const router = express.Router();

// Använd Helmet för att sätta säkra headers och skydda mot vissa attacker
router.use(helmet());

// Rate limiting middleware för att förhindra Brute Force-attacker
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuters fönster
  max: 5, // Tillåt högst 5 förfrågningar per fönster
  message: 'Too many requests from this IP, please try again later.',
});

// Använd rate limiting för alla förfrågningar till denna route
router.use('/', limiter);

router.get('/', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).send('Access Denied');

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified.role === 'admin') {
      res.json({ data: 'Secret data for admin!' });
    } else {
      res.json({ data: 'Secret data for user!' });
    }
  } catch (error) {
    // Logga fel för ytterligare undersökning
    console.error('Error verifying token:', error);
    res.status(401).send('Invalid Token');
  }
});

module.exports = router;
