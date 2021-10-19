// require("dotenv").config();
// const jwt = require("jsonwebtoken");
const express = require("express");
const JWTFunctions = require("./jwt");

const app = express();
app.use(express.json());

// array where the refresh token will be stored;
let refreshTokens = [];

// create access token
app.post("/login",(req,res)=>{
    let user = {
        username : req.body.username,
        password : req.body.password
    }
    let accessToken = JWTFunctions.createAccessToken(user);
    let refreshToken = JWTFunctions.refreshToken(user);
    refreshTokens.push(refreshToken);
    res.json({accessToken: accessToken, refreshToken: refreshToken});
})

// token validity
app.get("/login",JWTFunctions.authentification,(req,res)=>{
    res.json({data: req.user})
})

// refresh token
app.post("/token",(req,res)=>{
    let refreshToken = req.body.token;
    if(refreshToken == null || !refreshTokens.includes(refreshToken)) return res.status(401).send("401 - non authorized");
    let createNewToken = JWTFunctions.verifyRefreshToken(refreshToken);
    res.json({newToken: createNewToken});
})

app.listen(8000,(err)=>{
    if(err) throw err;
    console.log("Listening to the port 8000...");
})