const db = require("../models");
const config = require("../config/auth.config");
const User = db.user;
const Role = db.role;

const Op = db.Sequelize.Op;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

function getHashedPassword(clearPassword) {
    return bcrypt.hashSync(clearPassword, 8);
}
function comparePasswordWithHash(providedPw, hashedPw) {
    return bcrypt.compareSync(
        providedPw,
        hashedPw
    );
}
function getAccessToken(userId) {
    return jwt.sign({ id: userId },config.secret, {
        expiresIn: 86400 // 24 hours
    });
}
function getAuthorities(roles) {
    var authorities = [];
    for (let i = 0; i < roles.length; i++) {
        authorities.push("ROLE_" + roles[i].name.toUpperCase());
    }
    return authorities;
}

exports.signup = (req, res) => {
    //save User to database
    User.create({
        username: req.body.username,
        email: req.body.email,
        password: getHashedPassword(req.body.password)
    })
        .then(user => {
            if (req.body.roles) {
                Role.findAll({
                    where: {
                        name: {
                            [Op.or]: req.body.roles
                        }
                    }
                }).then(roles => {
                    user.setRoles(roles).then(() => {
                        res.send({ message: "User was registered successfully!" });
                    });
                });
            }
            else {
                user.setRoles([1]).then(() => {
                    res.send({ message: "User was registered successfully!" });
                });
            }
        })
        .catch(err => {
            res.status(500).send({ message: err.message });
        });
};

exports.signin = (req, res) => {
    User.findOne({
        where: {
            username: req.body.username
        }
    })
        .then(user => {
            if (!user) {
                res.status(404).send({ message: "User not found." });
            }
            if (!comparePasswordWithHash(req.body.password, user.password)) {
                return res.status(401).send({
                    accessToken: null,
                    message: "Invalid Password!"
                });
            }

            var token = getAccessToken(user.id);
            var authorities = getAuthorities(user.getRoles());

            res.status(200).send({
                id: user.id,
                username: user.username,
                email: user.email,
                roles: authorities,
                accessToken: token
            });
        }).catch(err => {
            res.status(500).send({ message: err.message });
        });
};

