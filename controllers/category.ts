import Category from "../models/category";

import { Router,Request,Response } from "express";
const router= Router()

const shoppingCategories = [
    "Men's Shirts",
    "Women's Shirts",
    "Men's Pants",
    "Women's Pants",
    "Men's Shoes",
    "Women's Shoes",
    "Kids' Clothing",
    "Accessories",
    "Jewelry",
    "Watches",
    "Handbags",
    "Backpacks",
    "Luggage",
    "Sunglasses",
    "Hats",
    "Scarves",
    "Gloves",
    "Belts",
    "Socks",
    "Underwear",
    "Swimwear",
    "Athletic Wear",
    "Activewear",
    "Outerwear",
    "Dresses",
    "Skirts",
    "Blouses",
    "Suits",
    "Ties",
    "Formalwear",
    "Costumes",
    "Uniforms",
    "Sleepwear",
    "Loungewear",
    "Maternity Clothing",
    "Pet Clothing",
    "Pet Accessories",
    "Home Decor",
    "Furniture",
    "Bedding",
    "Bath",
    "Kitchenware",
    "Dining",
    "Cookware",
    "Tableware",
    "Home Appliances",
    "Electronics",
    "Computers",
    "Laptops",
    "Tablets",
    "Smartphones",
    "Televisions",
    "Speakers",
    "Headphones",
    "Cameras",
    "Gaming",
    "Video Games",
    "Board Games",
    "Books",
    "Magazines",
    "Music",
    "Movies",
    "TV Shows",
    "Art",
    "Crafts",
    "Hobbies",
    "Toys",
    "Outdoor Gear",
    "Camping",
    "Hiking",
    "Fishing",
    "Cycling",
    "Exercise Equipment",
    "Sporting Goods",
    "Fitness Accessories",
    "Yoga",
    "Golf",
    "Skiing",
    "Snowboarding",
    "Surfing",
    "Skateboarding",
    "Boating",
    "Travel",
    "Luggage",
    "Travel Accessories",
    "Travel Electronics",
    "Car Accessories",
    "Motorcycle Gear",
    "RV Accessories",
    "Gardening",
    "Plants",
    "Outdoor Furniture",
    "Outdoor Lighting",
    "Patio Decor",
    "Pool Supplies",
    "Grilling",
    "BBQ Accessories",
    // Adding more categories to reach 100
    "Office Supplies",
    "Stationery",
    "Writing Instruments",
    "Desk Accessories",
    "Paper Products",
  ].map((e)=>({name:e}))
  

  router.get('/', async (req: Request, res: Response) => {
    try {
        console.log(req?.query);
        const page: number = parseInt(req?.query?.page as string, 10) || 1;
        const limit: number = parseInt(req?.query?.limit as string, 10) || 10;
        const totalItems = await Category.countDocuments({}); 
        const totalPages = Math.ceil(totalItems / limit);
        const data = await Category.find({})
            .limit(limit)
            .skip((page - 1) * limit)
            .lean();
        
        res.status(200).json({data,page,limit,totalPages});
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})
router.get('/create',async(req:Request,res:Response)=>{
    let sai=  await Category.insertMany(shoppingCategories)
    res.status(200).json(sai)
})


export default router