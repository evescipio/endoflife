import * as crypto from "crypto";
import * as mongoose from "mongoose";
import * as bcrypt from "bcrypt-nodejs";

export type UserModel = mongoose.Document & {
    email: string,
    password: string,
    userID: number,
    name: string,
    ownerHash: string,
    corporation: number,

    tokens: AuthToken[],

    profile: {
        gender: string,
        location: string,
        timezone: number,
        website: string
    },

    comparePassword: (candidatePassword: string, cb: (err: any, isMatch: any) => {}) => void
};

export type AuthToken = {
    accessToken: string,
    kind: string
};

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    userID: { type: Number, unique: true },
    name: String,
    ownerHash: String,
    corporation: Number,

    profile: {
        gender: String,
        location: String,
        timezone: Number,
        website: String
    }
}, { timestamps: true });

/**
 * Password hash middleware.
 */
userSchema.pre("save", function save(next) {
  const user = this;
  if (!user.isModified("password")) { return next(); }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) { return next(err); }
    bcrypt.hash(user.password, salt, undefined, (err: mongoose.Error, hash) => {
      if (err) { return next(err); }
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function (candidatePassword: string, cb: (err: any, isMatch: any) => {}) {
  bcrypt.compare(candidatePassword, this.password, (err: mongoose.Error, isMatch: boolean) => {
    cb(err, isMatch);
  });
};

const User = mongoose.model("User", userSchema);
export default User;