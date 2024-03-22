
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
interface AuthenticatedRequest extends Request {
    user?: any; 
}
export const verifyToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    console.log(process.env.JWT_SECRET)
    
    
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Access denied. Token not provided' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Error verifying token:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};
