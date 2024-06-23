const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
    try {
        const authHeader = req.headers.token;
        if (authHeader) {
            const token = authHeader.split(" ")[1];
            jwt.verify(token, process.env.JWT_SEC, (err, user) => {
                if (err) {
                    throw new Error('Invalid token'); // Ném ra lỗi nếu xác thực token thất bại
                } else {
                    req.user = user;
                    next();
                }
            });
        } else {
            throw new Error('Invalid token');
        }
    } catch (error) {
        next(error)
    }
};

const verifyTokenAndAuthorization = async (req, res, next) => {
    try {
        verifyToken(req, res, () => {
            if (!req.user || !req.user.id) {
                throw new Error('User ID is missing'); // Ném ra lỗi với thông báo
            }

            if (req.user.id || req.user.isAdmin) {
                next();
            } else {
                res.status(403).json("You are restricted from perfoming this operation");
            }
        });


    } catch (error) {
        next(error);
    }
};

const verifyTokenAndAdmin = async (req, res, next) => {
    try {
        verifyToken(req, res, () => {
            if (!req.user || !req.user.id) {
                throw new Error('User ID is missing'); // Ném ra lỗi với thông báo
            }
            if (req.user.isAdmin) {
                next();
            } else {
                throw new Error('You have limited access');
            }
        })
    } catch (error) {
        next(error);
    }
};


const verifyTokenAndAgent = async (req, res, next) => {
    try {
        verifyToken(req, res, () => {
            if (!req.user || !req.user.id) {
                throw new Error('User ID is missing'); // Ném ra lỗi với thông báo
            }
            if (req.user.isAgent || req.user.isAdmin) {
                next();
            } else {
                res.status(403).json("You are restricted from perfoming this operation");
            }
        })


    } catch (error) {
        next(error);
    }
};

module.exports = { verifyToken, verifyTokenAndAuthorization, verifyTokenAndAdmin, verifyTokenAndAgent };
