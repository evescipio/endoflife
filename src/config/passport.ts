import * as _ from "lodash";
import * as https from "https";
import * as request from "request";
import * as passport from "passport";
// import * as passportEve from "passport-eve";
import * as passportLocal from "passport-local";

const passportEve = require("passport-eve");

import { default as User } from "../models/User";
import { Request, Response, NextFunction } from "express";


const EveStrategy = passportEve.Strategy;
const LocalStrategy = passportLocal.Strategy;

passport.serializeUser<any, any>((user, done) => {
    done(undefined, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

/**
 * Sign in using Email and Password.
 */
passport.use(new LocalStrategy({ usernameField: "email" }, (email, password, done) => {
  User.findOne({ email: email.toLowerCase() }, (err, user: any) => {
    if (err) { return done(err); }
    if (!user) {
      return done(undefined, false, { message: `Email ${email} not found.` });
    }
    user.comparePassword(password, (err: Error, isMatch: boolean) => {
      if (err) { return done(err); }
      if (isMatch) {
        return done(undefined, user);
      }
      return done(undefined, false, { message: "Invalid email or password." });
    });
  });
}));

/**
 * OAuth Strategy Overview
 *
 * - Check if user is a returning user.
 *   - If returning, sign in and we are done.
 *   - Else create a new account in the database.
 */
passport.use(new EveStrategy({
    clientID: process.env.CCP_ID,
    clientSecret: process.env.CCP_SECRET,
    callbackURL: process.env.CCP_CALLBACK_URL
},
(accessToken: any, refreshToken: any, profile: any, done: any) => {
    User.findOne({ userID: profile.characterID }, (err, existingUser) => {
        if (err) { return done(err); }
        if (existingUser) { return done(undefined, existingUser); }
        else {
            const user: any = new User();
            user.userID = profile.characterID;
            user.name = profile.characterName;
            user.ownerHash = profile.characterOwnerHash;
            let url = "https://esi.tech.ccp.is/latest/characters/" + profile.characterID + "/?datasource=tranquility";
            https.get(url, (res) => {
                let data = "";
                res.on("data", (chunk: any) => { data += chunk; });
                res.on("end", () => {
                    let json_data = JSON.parse(data);
                    user.race = json_data.race_id;
                    user.bloodline = json_data.bloodline_id,
                    user.ancestry = json_data.ancestry_id,
                    user.corporation.corpID = json_data.corporation_id;
                    url = "https://esi.tech.ccp.is/latest/corporations/names/?corporation_ids=" + json_data.corporation_id + "&datasource=tranquility";
                    data = "";
                    json_data = "";
                    https.get(url, (res) => {
                        res.on("data", (chunk: any) => { data += chunk; });
                        res.on("end", () => {
                            json_data = JSON.parse(data);
                            user.corporation.corpName = json_data[0].corporation_name;
                            console.log(json_data);
                            user.save((err: Error, user: any) => {
                                return done(err, user);
                            });
                        });
                    });
                });
            });
        }
    });
}));

/**
 * Login Required middleware.
 */
export let isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/");
};

/**
 * Authorization Required middleware.
 */
export let isAuthorized = (req: Request, res: Response, next: NextFunction) => {
    const provider = req.path.split("/").slice(-1)[0];

    if (_.find(req.user.tokens, { kind: provider })) {
        next();
    } else {
        res.redirect(`/auth/${provider}`);
    }
};

export let isEOLMember = (req: Request, res: Response, next: NextFunction) => {
    if (req.isAuthenticated()) {
        console.log(req.user.corporation.corpID);
        console.log(req.user.corporation.corpID == 480079747);
        if (req.user.corporation.corpID == 480079747) {
            return next();
        }
        res.redirect("/public");
    }
};