const localStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');


 function intialize(passport, getUserByEmail,getUserById){
    const authenticatedUser = async (email, password, done) => {
        const user = getUserByEmail(email);
        if(user == null){
            return done(null, false, {message:'No user with that email'})
        }

        try{

            if(await bcrypt.compare(password, user.password)){
                return done(null, user)
            } else{
                return done(null, false, {message: 'Password does not match'})
            }
        }
        catch(e){
            return done(e)
        }
    }
    passport.use(new localStrategy({ usernameField : 'email' },authenticatedUser))

    passport.serializeUser((user,done)=>done(null, user.id))
    passport.deserializeUser((id,done)=>{
        done(null, getUserById(id))
    })

}


module.exports = intialize;