import * as dotenv from "dotenv";
dotenv.config();
import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import { auth } from "./middleware/auth.js";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
// const MONGO_URL = "mongodb://127.0.0.1";
const MONGO_URL = process.env.MONGO_URL;
const PORT = process.env.PORT;
const client = new MongoClient(MONGO_URL); // dial
// Top level await
await client.connect(); // call
console.log("Mongo is connected !!!  ");
app.use(cors());
const keysecret = process.env.SECRET_KEY;

app.get("/", async function (request, response) {
  try {
    response.send("🙋‍♂️, 🌏 🎊✨ddhhd");
  } catch (error) {
    response.status(404).send({ message: "invalid url" });
  }
});

async function generateHashedPassword(password) {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

app.post("/signup", express.json(), async function (request, response) {
  const { username, password } = request.body;
  const name = await client
    .db("loginpage")
    .collection("login")
    .findOne({ username: username });
  if (name) {
    response.status(400).send({ message: "username already exist" });
  } else {
    const hashedpassword = await generateHashedPassword(password);
    const result = await client
      .db("loginpage")
      .collection("login")
      .insertOne({ username: username, password: hashedpassword });
    response
      .status(201)
      .json({ status: 201, message: "User added successfully" });
  }
});

app.post("/login", express.json(), async function (request, response) {
  const { username, password } = request.body;
  const name = await client
    .db("loginpage")
    .collection("login")
    .findOne({ username: username });
  if (!name) {
    response.status(400).send({ message: "invalid credentials" });
  } else {
    const storedpassword = await name.password;
    const isPasswordCheck = await bcrypt.compare(password, storedpassword);
    if (isPasswordCheck) {
      const token = jwt.sign({ id: name._id }, keysecret);
      response.send({ message: "Successfully  login", token: token });
    } else {
      response.status(400).send({ message: "invalid credentials" });
    }
  }
});

app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));

import nodemailer from "nodemailer";

var sender = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "k.vimal1213@gmail.com",
    pass: "zschvdeqpjyvqjnw",
  },
  tls: {
    rejectUnauthorized: false,
  },
});

app.post("/passwordlink", express.json(), async function (request, response) {
  const email = request.body;
  try {
    const name = await client
      .db("loginpage")
      .collection("login")
      .findOne({ username: email.username });
    const token = jwt.sign({ id: name._id }, keysecret, { expiresIn: "120s" }
      );
    const setusertoken = await client
      .db("loginpage")
      .collection("login")
      .updateOne(
        { _id: name._id },
        { $set: { newtoken: token } },
        { new: true }
      );
    if (setusertoken) {
      var composemail = {
        from: "k.vimal1213@gmail.com",
        to: email.username,
        subject: "sending email for password reset",
        text: `This link valid for 2 minitues http://localhost:5173/forgotpassword/${name._id}/${token}`,
      };
      sender.sendMail(composemail, function (error, info) {
        if (error) {
          // console.log("error", error);
          response.status(401).json({ status: 401, message: "Email not sent" });
        } else {
          // console.log("Email sent", info.response);
          response
            .status(201)
            .json({ status: 201, message: "Email sent successfully" });
        }
      });
    }
  } catch (error) {
    response.status(401).json({ status: 401, message: "Invalid user" });
  }
});

app.get("/forgotpassword/:id/:token", async function (request, response) {
  const { id, token } = request.params;
  try {
    const validuser = await client
      .db("loginpage")
      .collection("login")
      .findOne({ _id: new ObjectId(id), newtoken: token });
    const verifytoken = jwt.verify(token, keysecret);
    if (validuser && verifytoken) {
      response.status(201).json({ status: 201, validuser });
    } else {
      response
        .status(401)
        .json({ status: 401, message: "user does not exist" });
    }
  } catch (error) {
    response.status(401).json({ status: 401, error });
  }
});

app.post("/:id/:token", express.json(), async function (request, response) {
  const { id, token } = request.params;
  const { password } = request.body;
  try {
    const validuser = await client
      .db("loginpage")
      .collection("login")
      .findOne({ _id: new ObjectId(id), newtoken: token });
    const verifytoken = jwt.verify(token, keysecret);
    if (validuser && verifytoken) {
      const hashedpassword = await generateHashedPassword(password);
      const result = await client
        .db("loginpage")
        .collection("login")
        .updateOne(
          { _id: new ObjectId(id) },
          { $set: { password: hashedpassword } },
          { new: true }
        );
      response.status(201).json({ status: 201, result });
    } else {
      response
        .status(401)
        .json({ status: 401, message: "user does not exist" });
    }
  } catch (error) {
    response.status(401).json({ status: 401, error });
  }
});
