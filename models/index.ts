
import { connect } from "mongoose";

export const dataBaseConnection = async (url: string): Promise<void> => {
    try {
        await connect(url);
        console.log("Connected to MongoDB");
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        throw error;
    }
}
