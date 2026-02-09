const bcrypt = require('bcryptjs');
bcrypt.hash('staff@001', 10).then(console.log);