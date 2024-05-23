const router = require("express").Router();
const userController = require("../controllers/userController");
const { verifyTokenAndAuthorization, verifyTokenAndAdmin } = require("../middleware/verifyToken");


// UPADATE USER
router.put("/:id", verifyTokenAndAuthorization, userController.updateUser);

// DELETE USER

router.delete("/:id", verifyTokenAndAuthorization, userController.deleteUser);

// GET USER

router.get("/:id", verifyTokenAndAuthorization, userController.getUser);


// GET ALL USER

router.get("/", verifyTokenAndAdmin, userController.getAllUsers);


module.exports = router