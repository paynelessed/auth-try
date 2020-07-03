const monk = require('monk');
const db = monk('localhost/auth-coding-garden');

module.exports = db;
