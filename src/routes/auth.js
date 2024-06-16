const router = require("express").Router();
const authController = require("../controllers/authContoller");


// REGISTRATION 

router.post("/register", authController.createUser);
router.get("/test", (req, res) => {
  res.send("thanh cong")
});


// LOGIN 
router.post("/login", authController.loginUser);


module.exports = router