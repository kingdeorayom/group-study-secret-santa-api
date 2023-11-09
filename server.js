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

const USERS_ROUTER = require('./routes/users')

app.use('/users', USERS_ROUTER)

app.listen(port, () => console.log(`Server started on port ${port}`))