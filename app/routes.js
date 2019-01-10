module.exports = function (app, passport) {

    // =====================================
    // HOME PAGE (with login links) ========
    // =====================================
    app.get('/', function (req, res) {
        res.render('index.ejs'); // load the index.ejs file
    });

    // =====================================
    // LOGIN ===============================
    // =====================================
    // show the login form
    app.get('/login', function (req, res) {
        // render the page and pass in any flash data if it exists
        res.render('login.ejs', {message: req.flash('loginMessage')});
    });

    // process the login form
    app.post('/login', passport.authenticate('local-login', {
        successRedirect: '/profile', // redirect to the secure profile section
        failureRedirect: '/login', // redirect back to the signup page if there is an error
        failureFlash: true // allow flash messages
    })
  );

    // =====================================
    // SIGNUP ==============================
    // =====================================
    // show the signup form
    app.get('/signup', function (req, res) {
        // render the page and pass in any flash data if it exists
        res.render('signup.ejs', {message: req.flash('signupMessage')});
    });

    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect: '/profile', // redirect to the secure profile section
        failureRedirect: '/signup', // redirect back to the signup page if there is an error
        failureFlash: true // allow flash messages
    }));

    app.get('/confirm2fa', isLoggedIn, function (req, res) {
        res.render('confirm2fa.ejs', {
            user: req.user // get the user out of session and pass to template
        });
    });

    // app.post('/confirm2fa', confirm2FA('local-signup', {
        // successRedirect: '/confirm2fa', // redirect to the secure profile section
        // failureRedirect: '/', // redirect back to the signup page if there is an error
        // failureFlash: true // allow flash messages
    // }));

    // =====================================
    // PROFILE SECTION =====================
    // =====================================
    // we will want this protected so you have to be logged in to visit
    // we will use route middleware to verify this (the isLoggedIn function)
    app.get('/profile', isLoggedIn, function (req, res) {
        res.render('profile.ejs', {
            user: req.user // get the user out of session and pass to template
        });
    });

    // =====================================
    // LOGOUT ==============================
    // =====================================
    app.get('/logout', function (req, res) {
        req.logout();
        res.redirect('/');
    });

    app.get('/api/current_user', function(req,res) {
        res.send(req.user);
    });

    app.get('/api/current_session', function(req,res) {
        res.send(req.session);
    });


    // =====================================
    // TWITTER ROUTES ======================
    // =====================================





};

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {
    // if user is authenticated in the session, carry on
    if (req.isAuthenticated())
        return next();

    // if they aren't redirect them to the home page
    res.redirect('/');
}

function is2FALoggedIn(req, res, next) {
  // if user is authenticated in the session carry on

  // if they are't redirect them to the home page
  res.redirect('/');
}
