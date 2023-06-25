import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
dotenv.config();

export const auth=(request,response,next)=>{
    try{
        const token=request.header("x-auth-token");
        const keysecret = process.env.SECRET_KEY;
        jwt.verify(token,keysecret);
        next();
    }
    catch(err){
        response.status(401).send({message:"invalid token"})
    }
        next();
   
}