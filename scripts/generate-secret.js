import crypto from 'crypto';

// Generate a secure random JWT secret
const jwtSecret = crypto.randomBytes(32).toString('hex');

console.log('Generated JWT Secret:');
console.log(jwtSecret);
console.log('\nCopy this value to your .env.local file as JWT_SECRET=' + jwtSecret);
