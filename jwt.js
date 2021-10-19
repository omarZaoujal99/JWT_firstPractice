const jwt = require("jsonwebtoken");
require("dotenv").config();

// create access token
let createAccessToken = (data)=>{
    return jwt.sign(data,process.env.ACCESS_TOKEN_VALUE,{expiresIn:"30s"});
}

// create refresh token
let refreshToken = (data)=>{
    return jwt.sign(data,process.env.REFRESH_TOKEN_VALUE);
}

// authentification function
let authentification = (req,res,next)=>{
    // getting the token from the authorization in the header
    let getAuthorization = req.headers["authorization"];
    let token = getAuthorization.split(" ")[1]
    if(!token) return res.status(401).send("401 - non authorized");
    jwt.verify(token,process.env.ACCESS_TOKEN_VALUE,(err,data)=>{
        if(err) return res.status(403).send("403 - forbidden");
        req.user = data
        next();
    })
}

// verify the refresh token
let verifyRefreshToken = (token)=>{
    let newToken;
    jwt.verify(token, process.env.REFRESH_TOKEN_VALUE, (err, data) => {
        if (err) throw err;
        newToken = createAccessToken({
            username: data.username,
            password: data.password
        });
    })
    return newToken;
}

module.exports = {createAccessToken,authentification,refreshToken,verifyRefreshToken};
