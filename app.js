const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session(
  {
    secret: 'your-session-secret-key',
    resave: false,
    saveUninitialized: false
  }
));

const jwt = require('jsonwebtoken');

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String
});

const User = mongoose.model('User', userSchema);

// Connect to your MongoDB database
mongoose.connect('mongodb+srv://charith:charith@cluster0.1cezehf.mongodb.net/?retryWrites=true&w=majority', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to the database');
  })
  .catch(err => {
    console.error('Error connecting to the database:', err);
});

passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
  User.findOne({ email: email }, (err, user) => {
    if (err) { return done(err); }
    if (!user) { return done(null, false); }

    bcrypt.compare(password, user.password, (err, res) => {
      if (res) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    });
  });
}));

  
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
      done(err, user);
    });
  });
  
  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) {
      return res.sendStatus(200);
    }
  
    jwt.verify(token, 'your-secret-key', (err, decoded) => {
      if (err) {
        return res.sendStatus(200);
      }
  
      req.userId = decoded.userId;

      next();
    });
  };


// Configure multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Specify the destination directory where uploaded files will be stored
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    // Specify a custom filename for the uploaded file
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Handle file upload route
app.post('/upload', upload.single('file'), (req, res) => {
  // Access the uploaded file using req.file
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }

  // File was uploaded successfully
  res.send('File uploaded!');
});


app.post('/upload', upload.single('file'), (req, res) => {
  // Access the uploaded file using req.file
  if (!req.file) {
    return res.status(400).send('No files were uploaded.');
  }

  // File was uploaded successfully
  res.send('File uploaded!');
});

  app.post('/login', passport.authenticate('local'), (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, 'your-secret-key', { expiresIn: '1h' });
    res.json({ message: 'Login successful',token:token });
  });
  
  app.post('/register', (req, res) => {
    const { username, password, email } = req.query;
    User.findOne({ email: email }, (err, user) => {
      if (user) {
        return res.status(200).json({ message: 'Username exists', email:  email});
      }
  
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          return res.status(200).json({ message: 'pass error'});
        }
  
        const newUser = new User({ username: username, password: hash,email:email });
        newUser.save((err) => {
          if (err) {
            return res.status(200).json({ message: 'user add error' });
          }
  
          res.json({ message: 'Registration successful' });
        });
      });
    });

  });

  // A protected route that requires authentication
app.get('/profile', authenticateToken, (req, res) => {
  User.findById(req.userId, (err, user) => {
    if (err) {
      res.json({ name: '',email:'' });
    }
    res.json({ name: user.username,email:user.email  });
  });
  
  //res.json({ name: 'null' });
    //res.json({ name: req.user.username,  email: req.user.email, });
});

app.post('/logout', authenticateToken, (req, res) => {
  req.session.destroy(function (err) {
    //res.redirect('/'); //Inside a callback… bulletproof!
  });
  res.json({ message: 'Logout successful' });
});

app.post('/detect',upload.single('file'),  (req, res) => {
	if (!req.file) {
	    return res.status(400).send('No files were uploaded.');
	  }
	res.json({ result: 'Acne',file:'uploaded' });
});

app.post('/predict', (req, res) => {

	//res.json({ result: 'NO_CARDIO_DESEASE'});
	res.json({ result: 'NON'});
});

  
  // function isAuthenticated(req, res, next) {
  //   if (req.isAuthenticated()) {
  //     return next();
  //   }
  
  //   res.status(200).json({ message: 'Unauthorized' });
  // }

  
  

  app.listen(3000, () => {
    console.log('Server listening on port 3000');
  });


    
