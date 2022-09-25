const jwt = require("jsonwebtoken");

const config = process.env;

const verifyTokenAdmin = (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers["x-access-token"];

  if (!token) {
    return res.status(401).send("A token is required for authorization");
  }
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
    console.log(req.user)

    if (req.user.role !== "0") {
      return res.status(403).send("Insufficient privileges!");
    }
  } catch (err) {
    return res.status(401).send("Invalid Token");
  }
  return next();
};

module.exports = verifyTokenAdmin;