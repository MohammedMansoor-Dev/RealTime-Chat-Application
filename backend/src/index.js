import { app, server } from './lib/socket.js'
import express from 'express'
import authRoutes from './routes/auth.route.js'
import messageRoutes from './routes/message.route.js'
import dotenv from 'dotenv'
import {connectDB} from './lib/db.js'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import path from 'path'

dotenv.config()

const port = process.env.PORT || 3000
const __dirname = path.resolve()

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}))

connectDB()

app.use('/api/auth', authRoutes)
app.use('/api/messages', messageRoutes)

if(process.env.NODE_ENV === 'production'){
    app.use(express.static(path.join(__dirname, '../frontend/dist')))

    app.get('*', (req, res)=>{
        res.sendFile(path.join(__dirname, '../frontend', 'dist', 'index.html'))
    })
}

server.listen(port, ()=>console.log(`Server is listening on port: ${port}`))