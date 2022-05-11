const { isLoggedIn, isLoggedOut } = require("../middleware/logs-guard");
const router = require("express").Router();

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/profile", isLoggedIn, (req, res, next) => {
  res.render("profile", { user: req.session.currentUser });
});
module.exports = router;
