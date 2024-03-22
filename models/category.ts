
import mongoose, { Schema, Document } from 'mongoose';

export interface CategoryModel extends Document {
  name: string;
}

const CategorySchema: Schema = new Schema({
  name: { type: String, required: true }
});

const Category = mongoose.model<CategoryModel>('Category', CategorySchema);

export default Category;
