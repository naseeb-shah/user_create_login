import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';

import * as dotenv from 'dotenv';
import { dataBaseConnection } from './models';
const env:any=dotenv.config().parsed;
import CategoryRoute from './controllers/category'
import UserRoute from './controllers/user'
import { verifyToken } from './middleware';
// Define a type for a shopping category
interface Category {
  id: number;
  name: string;
}

// In-memory storage for categories
let categories: Category[] = [];

// Express app
const app = express();
const port = 3002;
app.use(cors());
app.use(express.json())

// Middleware
app.use(bodyParser.json());

// Routes
app.use('/categories',verifyToken,CategoryRoute)
app.use('/user',UserRoute)

const dbUrl:any = env.DB_URL;
console.log(dbUrl)

 dataBaseConnection(dbUrl).then((e)=>{
    app.listen(port, () => {

        console.log(`Server is listening on port ${port}`);
      });
 }).catch((e)=>console.log(e))
// Start server

