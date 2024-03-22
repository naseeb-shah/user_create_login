
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
interface AuthenticatedRequest extends Request {
    user?: any; 
}
export const verifyToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    console.log("sai")
    
    
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Access denied. Token not provided' });
    }
    try {
        const decoded = jwt.verify(token, "sai");
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Error verifying token:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};
