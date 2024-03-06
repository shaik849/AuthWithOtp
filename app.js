const express = require('express')
const app = express();
require('dotenv').config();
const mongoose = require('mongoose');
const morgan = require('morgan');
const cors = require('cors');
app.set('view engine', 'ejs');
let DB_URL = process.env.DATABASE_URL
let authRouter = require('./Router/Auth')

app.use(morgan('dev'))
app.use(cors('*'));
var bodyParser = require('body-parser');
app.use(bodyParser.json({ limit: '50mb' }));
app.use(express.json({ limit: '50mb', extended: true, parameterLimit: 50000 }));
app.use(express.text({ limit: '50mb', type: 'text/html' }));
// next();
// express.json()(req, res, next);  // ONLY do express.json() if the received request is NOT a WebHook from Stripe.
//   }
// });

app.use(express.urlencoded({ limit: '50mb', extended: true }));

mongoose.connect(DB_URL).then(() => {
    console.log('connected....');
}).catch(err => {console.error(err);});


// app.listen(process.env.PORT, () => {
//     console.log("listening on port 3000")
// })

  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Handle the error or log additional information
    // Note: This is a global handler for unhandled promise rejections
  });
app.use('/api',authRouter)
  

module.exports = app
  
  