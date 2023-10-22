require('dotenv').config()

const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')

const port = 3001
const app = express()

mongoose.connect(process.env.DATABASE_URL, { dbName: 'gssecretsanta', useNewUrlParser: true, useUnifiedTopology: true })

const db = mongoose.connection
db.on('error', (error) => console.error(error))
db.once('open', () => console.log('Connected to Database'))

app.use(cors())
app.use(express.json())

// const brandsRouter = require('./routes/brands')
// const searchRouter = require('./routes/search')
// const vehicleRouter = require('./routes/vehicles')
// const inquiriesRouter = require('./routes/inquiries')
const usersRouter = require('./routes/users')
// const sampleRouter = require('./routes/samples')

// app.use('/brands', brandsRouter)
// app.use('/search', searchRouter)
// app.use('/vehicles', vehicleRouter)
// app.use('/inquiries', inquiriesRouter)
app.use('/users', usersRouter)
// app.use('/samples', sampleRouter)

// app.use('/images', express.static('images'));


app.listen(port, () => console.log(`Server started on port ${port}`))