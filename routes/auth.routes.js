const router = require("express").Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const User = require("../models/User.model");
const saltRounds = 5;
const { isLoggedIn, isLoggedOut } = require("../middleware/logs-guard");

router.get("/signup", isLoggedOut, (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", isLoggedOut, (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.render("auth/signup", { errorMessage: "All fields required" });
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res.status(500).render("auth/signup", {
      errorMessage:
        "Password must contain at least 6 characters, one uppercase, one lowercase and one special characters",
    });
  }

  bcrypt
    .genSalt(saltRounds)
    .then((salt) => {
      return bcrypt.hash(password, salt);
    })
    .then((hashedPassword) => {
      return User.create({
        username,
        password: hashedPassword,
      });
    })
    .then(() => res.redirect("/profile"))
    .catch((err) => {
      if (err instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: err.message });
      } else if (err.code === 11000) {
        res.status(500).render("auth/signup", {
          errorMessage: "Your username has already been taken",
        });
      } else {
        next(err);
      }
    });
});

router.get("/login", isLoggedOut, (req, res, next) => res.render("auth/login"));

router.post("/login", isLoggedOut, (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.render("auth/login", { errorMessage: "All fields required" });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        res.render("auth/login", { errorMessage: "User not found" });
        return;
      } else if (bcrypt.compareSync(password, user.password)) {
        req.session.currentUser = user;
        req.app.locals.currentUser = user;

        res.render("profile", { user });
      } else {
        res.render("auth/login", { errorMessage: " Incorrect passoword" });
      }
    })
    .catch((err) => next(err));
});

router.get("/main", isLoggedIn, (req, res, next) => res.render("main"));
router.get("/private", isLoggedIn, (req, res, next) => res.render("private"));

router.get("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    if (err) next(err);
    res.redirect("/");
  });
});

module.exports = router;
