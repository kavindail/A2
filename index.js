
require("./utils.js");

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 4500;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;


var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {
        maxAge: expireTime
    }
}
));

app.set('view engine', 'ejs');




app.get('/', (req, res) => {
    var missingEmail = req.query.missing;
 
    if (missingEmail) {
        html2 += "<br> email is required";
    }
    res.render("index");

});

app.get('/signup', (req, res) => {
    var missingEmail = req.query.missing;
    
    res.render("signup");
});


app.post('/signupsubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    if (!name || !email || !password) {
        const errorMessage = 'Please fill in all three fields.';
        const html = `
        <p>${errorMessage}</p>
        <a href="/signup?missing=true">Back to signup page</a>
      `;
        res.send(html);
        return;
    }
    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
        const errorMessage = 'An account with this email address already exists.';
        const html = `
        <p>${errorMessage}</p>
        <a href="/signup">Back to signup page</a>
      `;
        res.send(html);
        return;
    }

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = { name, email, password: hashedPassword , userType: 'user'};
        const result = await userCollection.insertOne(newUser);
        console.log(`Created new user: ${result.insertedId}`);

        req.session.name = name;
        req.session.email = email;

        res.redirect('/members');

    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});




app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});




app.get('/login', (req, res) => {
    var missingCredentials = req.query.missing;
    var loginFailed = req.query.failed;
  
    if (missingCredentials) {
    "<br> Email and password are required";
    }
    if (loginFailed) {
      "<br> Login failed";
    }
    res.render("login");
});

app.post('/loginsubmit', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    if (email && !password) {
        const errorMessage = 'Invalid password.';
        const html = `
            <p>${errorMessage}</p>
            <a href="/login?missing=true">Try again</a>
        `;
        res.send(html);
        return;
    }
    if (!email || !password) {
        const errorMessage = 'Invalid email/password combination.';
        const html = `
            <p>${errorMessage}</p>
            <a href="/login?missing=true">Try again</a>
        `;
        res.send(html);
        return;
    }

    const existingUser = await userCollection.findOne({ email });
    if (!existingUser) {
        const errorMessage = 'Invalid email/password combination.';
        const html = `
            <p>${errorMessage}</p>
            <a href="/login">Try again</a>
        `;
        res.send(html);
        return;
    }

    try {
        const passwordMatches = await bcrypt.compare(password, existingUser.password);
        if (!passwordMatches) {
            const errorMessage = 'Invalid password .';
            const html = `
                <p>${errorMessage}</p>
                <a href="/login?failed=true">Try again</a>
            `;
            res.send(html);
            return;
        }
        
        req.session.userId = existingUser._id;
        req.session.email = existingUser.email;
        req.session.name = existingUser.name;
        req.session.loggedIn = true;
        req.session.userType = existingUser.userType; // set the userType from the newUser object
        req.session.save();
        res.redirect('/members');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/members2', requireAuth, (req, res) => {
    const { name } = req.session;

    res.send(`
      <p>Hello ${name}!</p>
      <form action="/membersPage" method="get">
        <input type="hidden" name="name" value="${name}">
        <button type="submit">Go to Members Area</button>
      </form>
      <form action="/logout" method="POST">
        <button type="submit">Log out</button>
      </form>
    `);
 

});


app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword });
    console.log("Inserted user");

    var html = "successfully created user";
    res.send(html);
});

app.get('/cat/:id', (req, res) => {
    const catIds = ['1', '2', '4'];
    const catId = req.params.id;

    if (catIds.includes(catId)) {
        const catNames = {
            '1': 'Fluffy',
            '2': 'Socks',
            '4': 'Mittens'
        };
        const catName = catNames[catId];
        const catGifs = {
            '1': '/fluffy.gif',
            '2': '/socks.gif',
            '4': '/cat4.gif'
        };
        const catGif = catGifs[catId];

        res.send(`${catName}: <img src='${catGif}' style='width:250px;'>`);
    } else {
        res.send(`Invalid cat id: ${catId}`);
    }
});
// server.js
app.get('/members', requireAuth, (req, res) => {
    const { name } = req.session;
    const catGifs = {
      '1': '/fluffy.gif',
      '2': '/socks.gif',
      '4': '/cat4.gif'
    };
    const catIds = Object.keys(catGifs); // Get all cat IDs from catGifs object
    const catGif1 = catGifs[catIds[0]]; // Get the first cat GIF
    const catGif2 = catGifs[catIds[1]]; // Get the second cat GIF
    const catGif3 = catGifs[catIds[2]]; // Get the third cat GIF
  
    res.render('cats', { name, catGif1, catGif2, catGif3 });
  });
  
  


function requireAuth(req, res, next) {
    if (!req.session.email) {
        res.redirect('/');
    } else {
        next();
    }
}


app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    var html = `
    You are logged out.
    `;
    res.send(html);
});




function isAdmin(req, res, next) {
    if (!req.session || !req.session.userType) {
      res.redirect('/login');
    } else if (req.session.userType !== 'admin') {
      res.status(403).render('403');
    } else {
      next();
    }
  }
  
  app.get('/admin', isAdmin, async (req, res) => {
    const users = await userCollection.find().toArray();
    res.render('admin', { users });
  });
  
  
  // Route to promote a user to admin
  app.post('/promote', isAdmin, async (req, res) => {
    const { email } = req.body;
    
    // Check if user exists
    const user = await userCollection.findOne({ email });
    if (!user) {
      res.status(400).send('User not found');
      return;
    }
    
    // Check if user is already an admin
    if (user.userType === 'admin') {
      res.redirect('/admin');
      return;
    }
    
    // Update user's userType to admin
    const result = await userCollection.updateOne(
      { email },
      { $set: { userType: 'admin' } }
    );
    
    // Check if update was successful
    if (result.modifiedCount === 1) {
      res.redirect('/admin');
    } else {
      res.status(500).send('Internal Server Error');
    }
  });
  
  // Route to demote an admin to user
  app.post('/demote', isAdmin, async (req, res) => {
    const { email } = req.body;
    
    // Check if user exists
    const user = await userCollection.findOne({ email });
    if (!user) {
      res.status(400).send('User not found');
      return;
    }
    
    // Check if user is a user (i.e., not an admin)
    if (user.userType !== 'admin') {
      res.redirect('/admin');
      return;
    }
    
    // Update user's userType to user
    const result = await userCollection.updateOne(
      { email },
      { $set: { userType: 'user' } }
    );
    
    // Check if update was successful
    if (result.modifiedCount === 1) {
      res.redirect('/admin');
    } else {
      res.status(500).send('Internal Server Error');
    }
  });
  


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 
