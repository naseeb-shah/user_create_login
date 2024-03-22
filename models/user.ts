
import mongoose, { Schema, Document } from 'mongoose';

export interface UserModel extends Document {
  username: string;
  email: string;
  password: string;
}

const UserSchema: Schema = new Schema({
  username: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true }
});

const User = mongoose.model<UserModel>('User', UserSchema);

export default User;
