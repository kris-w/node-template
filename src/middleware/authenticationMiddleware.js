require('dotenv').config(); // Import dotenv and load environment variables

const jwt = require("jsonwebtoken");
const uuidv4 = require("uuid").v4;

const isAuthenticated = (req, res, next) => {
  console.log ("checking login..");
  const authHeader = req.headers.authorization;
  console.log(authHeader);
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
      if (err) {
        return res.status(403).json({ message: "Invalid or expired token." });
      }
      // Renew token if necessary
      renewToken(req, res, () => {
        req.tokenDecoded = decodedToken;
        next();
      });
    });
  } else {
    res.sendStatus(401);
  }
};

const authenticateAndDecode = (token) => {
  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    return decodedToken;
  } catch (err) {
    return false;
  }
};

const decodeValidToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
      if (!err) {
        req.tokenDecoded = decodedToken;
      }
      next();
    });
  } else {
    next();
  }
};

const renewToken = (req, res, next) => {
  const tokenDecoded = req.tokenDecoded;
  if (tokenDecoded) {
    const expirationDate = new Date(tokenDecoded.exp * 1000);
    const twentyMinutesFromNow = new Date(Date.now() + 20 * 60 * 1000);
    if (expirationDate < twentyMinutesFromNow) {
      const newToken = createJWT(tokenDecoded, "token-renewal");
      res.header("auth-token", newToken.token);
      res.header("auth-token-decoded", JSON.stringify(newToken.tokenDecoded));
    }
    next();
  } else {
    next();
  }
};

function createJWT(account, source) {
  const tokenDecoded = {
    username: account.username,
    roles: account.roles,
    aud: process.env.JWT_AUDIENCE, // Fetch from .env
    iss: source,
    nbf: Math.floor(Date.now() / 1000),
    jti: uuidv4(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // one hour
  };
  const token = jwt.sign(tokenDecoded, process.env.JWT_SECRET);
  return { token, tokenDecoded };
}

const isAdmin = (req, res, next) => {
  const roles = req.tokenDecoded?.roles || [];
  if (!roles.includes("admin")) {
    return res
      .status(403)
      .send({ message: "Access denied. Only admins can perform this action." });
  }
  next();
};

module.exports = {
  isAuthenticated,
  decodeValidToken,
  renewToken,
  createJWT,
  isAdmin,
  authenticateAndDecode,
};
