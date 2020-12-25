const express = require('express');
const app = express()
const bcrypt = require('bcryptjs');
const flash = require('express-flash');
const session = require('express-session');
const config = require('config');
const passport = require('passport');
const methodOverride = require('method-override');

const initializedUser = require('./passport.config');



initializedUser(passport, 
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id),
    );

let users = [];

app.set('view-engine','ejs')

app.use(express.urlencoded({extended:false}));
app.use(flash())
app.use(session({
    secret: config.get('secret_session'),
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session());
app.use(methodOverride('_method'))


app.get('/', checkAuthenticated,(req,res)=>{
    res.render('index.ejs',{name:req.user.name});
})


app.get('/login', (req,res)=>{
    res.render('login.ejs');
})


app.get('/register', (req,res)=>{
    res.render('register.ejs');
})


app.post('/register',checkNotAuthenticated,async (req,res)=>{
   try{
       let hashedPassword = await bcrypt.hash(req.body.password,10);
       users.push({
           id: Date.now().toString(),
           name: req.body.name,
           email:req.body.email,
           password: hashedPassword
       })
       res.redirect('/login')
   }
   catch{
       res.redirect('/register')
   }
   console.log(users)
})



app.post('/login',checkNotAuthenticated, passport.authenticate('local',{
    successRedirect:'/',
    failureRedirect:'/login',
    failureFlash: true
}));


// logout route
app.delete('/logout', (req,res)=>{
    req.logOut()
    res.redirect('/login')
})


function checkAuthenticated(req,res, next){
    if(req.isAuthenticated){
        return next()
    }

    res.redirect('/login')
}


function checkNotAuthenticated(req,res, next){
    if(req.isAuthenticated()){
        return res.redirect('/')
    }
    next()
}
const port = process.env.PORT || 5000
app.listen(port, ()=> console.log(`server run on port ${port}`));