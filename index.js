import * as dotenv from "dotenv";
dotenv.config();
import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const app = express();
// app.use(cors())
app.use(cors({ origin: "*" }));
// const MONGO_URL = "mongodb://127.0.0.1";
const MONGO_URL = process.env.MONGO_URL;
const PORT = process.env.PORT;
const client = new MongoClient(MONGO_URL); // dial
// Top level await
await client.connect(); // call
console.log("Mongo is connected !!!  ");

async function generateHashedPassword(password) {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

app.post("/signup", express.json(), async function (request, response) {
  const { username, password } = request.body;
  const name = await client
    .db("rental")
    .collection("login")
    .findOne({ username: username.toLowerCase() });
  console.log(name);
  if (name) {
    response.status(400).send({ message: "username already exist" });
  } else {
    const hashedpassword = await generateHashedPassword(password);
    const result = await client.db("rental").collection("login").insertOne({
      username: username.toLowerCase(),
      password: hashedpassword,
    });
    response.send(name);
  }
});

app.post("/login", express.json(), async function (request, response) {
  const { username, password } = request.body;
  const name = await client
    .db("rental")
    .collection("login")
    .findOne({ username: username });
  if (!name) {
    response.status(400).send({ message: "invalid credentials" });
  } else {
    const storedpassword = await name.password;
    const isPasswordCheck = await bcrypt.compare(password, storedpassword);
    if (isPasswordCheck) {
      const token = jwt.sign({ id: name._id }, "thisismytoken");
      response.send({ message: "Successfully  login", token: token });
    } else {
      response.status(400).send({ message: "invalid credentials" });
    }
  }
});

app.post("/passwordlink", express.json(), async function (req, res) {
  console.log(req.body);
  const { username } = req.body;
  const emailpresent = await client
    .db("rental")
    .collection("login")
    .findOne({ username: username.toLowerCase() });
  console.log(emailpresent);
  if (emailpresent) {
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
    console.log(
      `Click the link to reset password: ${req.headers.origin}/forgotpassword/${emailpresent._id}`
    );
    var composemail = {
      from: "k.vimal1213@gmail.com",
      to: username,
      subject: "Reset password link",
      text: `Click the link to reset password: ${req.headers.origin}/forgotpassword/${emailpresent._id}`,
    };

    sender.sendMail(composemail, function (error, info) {
      if (error) {
        console.log(error, error.response);
        console.log("error");
      } else {
        res.status(200).send({ message: "mail sent successfully", code: 200 });
        console.log("mail sent successfully" + info.response);
      }
    });
  } else {
    res.status(200).send({ message: "EmailId not present", code: 400 });
  }
});

app.get("/forgotpassword/:id", express.json(), async function (req, res) {
  const id = req.params["id"];
  const emailpresent = await client
    .db("rental")
    .collection("login")
    .findOne({ _id: new ObjectId(id) });
  if (emailpresent) res.status(200);
  else res.status(400);
});

app.post("/forgotpassword/:id", express.json(), async function (req, res) {
  const id = req.params["id"];
  const emailpresent = await client
    .db("rental")
    .collection("login")
    .findOne({ _id: new ObjectId(id) });
  console.log(emailpresent);
  if (emailpresent) {
    const hashedpassword = await generateHashedPassword(req.body.password);
    const result = await client
      .db("rental")
      .collection("login")
      .updateOne(
        {
          _id: new ObjectId(id),
        },
        { $set: { password: hashedpassword } }
      );
    console.log(result);
    if (result) {
      console.log("dd");
      res.status(200).send({ message: "Password updated" });
    } else {
      res.status(400).send({ message: "somthing error in updating password" });
    }
  } else res.status(400).send({ message: "invalid credentials" });
});

app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));
