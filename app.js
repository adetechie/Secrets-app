const passportLocalMongoose = require("passport-local-mongoose"),
GoogleStrategy = require("passport-google-oauth20").Strategy,
findOrCreate = require("mongoose-findorcreate"),
session = require("express-session"),
bodyParser = require("body-parser"),
passport = require("passport"),
mongoose = require("mongoose"),
express = require("express"),
dotenv = require("dotenv"),
ejs = require("ejs"),
app = express();
dotenv.config();


app.set("view engine", "ejs");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));


app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URI, {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACKURL,
    userProfileURL: process.env.USERPROFILEURL
},
function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    
    User.findOrCreate({ googleId: profile.id }, (err, user) => {
        return cb(err, user);
    });
}
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
passport.authenticate('google', { failureRedirect: "/login" }),
(req, res) => {

    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
});

app.get("/secrets", (req, res) =>{
    User.find({"secret": {$ne: null}}, (err, foundUsers) => {
        if (err){
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.route("/login")
.get((req, res) => {
    res.render("login");
})

.post((req, res) => {
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});



app.route("/register")
.get((req, res) => {
    res.render("register");
})

.post((req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});


app.route("/submit")
.get((req, res) => {
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})
.post((req, res) => {
    const submittedSecret = req.body.secret;
    //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);
    
    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
        }else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, () => {
    console.log("Server has started successfully");
});