const jwt = require("jsonwebtoken");
const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;

verifyToken = (req, res, next) => {
    let token = req.headers["x-access-token"];

    if (!token) {
        return res.status(403).send({
            message: "No token provided!"
        });
    }

    jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
            return res.status(401).send({
                message: "Unauthorized!"
            });
        }
        req.userId = decoded.id;
        next();
    });
};

isAdmin = (req, res, next) => {
    User.findByPk(res.userId).then(user => {
        user.getRoles().then(roles => {
            if (containsRole(roles, "admin")) {
                next();
                return;
            }
            res.status(403).send({
                message: "Require Admin Role!"
            });
            return;
        });
    });
};
isModerator = (req, res, next) => {
    User.findByPk(res.userId).then(user => {
        user.getRoles().then(roles => {
            if (containsRole(roles, "moderator")) {
                next();
                return;
            }
            res.status(403).send({
                message: "Require Moderator Role!"
            });
        });
    });
};

isModeratorOrAdmin = (req, res, next) => {
    User.findByPk(req.userId).then(user => {
        user.getRoles().then(roles => {
            if (containsRole(roles, "admin") || containsRole(roles, "moderator")){
                next();
                return;
            }
            res.status(403).send({
                message: "Require Moderator or Admin Role!"
            });
        });
    });
};

function containsRole(roles, targetRole) {
    for (let i = 0; i < roles.length; i++) {
        if (roles[i].name === targetRole) {
            return true;
        }
    }
    return false;
}

const authJwt = {
    verifyToken: verifyToken,
    isAdmin: isAdmin,
    isModerator: isModerator,
    isModeratorOrAdmin: isModeratorOrAdmin
};

module.exports = authJwt;