module.exports = {
    HOST: "192.168.178.73",
    USER: "root",
    PASSWORD: "Test123!",
    DB: "nodeBackend",
    dialect: "mysql",
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
};