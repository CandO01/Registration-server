import http from 'http'
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt'

dotenv.config();

const PORT = 3446;

const JWT_SECRET = process.env.JWT_SECRET;

let users = [];

const server = http.createServer(async(req, res)=>{
    res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE',
      'Access-Control-Allow-Headers': 'Content-Type'
    })
    res.end()
    return
  }
  // helper sendJSON;

  const sendJSON = (status, obj)=>{
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(obj))
  }

  // POST for /signup route

  if(req.url === '/signup' && req.method === 'POST'){
     let body = '';
     req.on('data', chunk => body += chunk.toString());
     req.on('end', async()=>{
        try {
          const { name, phone, email, password, confirm } = JSON.parse(body)
          if(!name || !phone || !email || !password || !confirm) return sendJSON(400, { message: 'All fields are required' });

          // confirm if password is thesame as confirm password
          if(password !== confirm) return sendJSON(401, { message: 'Password is not thesame' });

          const existingUser = users.find(u => u.email === email)
          if(existingUser) return sendJSON(409, { message: 'User already exist' });

          const hashedPassword = await bcrypt.hash(password, 10);
          users.push({
            name,
            phone,
            email,
            password: hashedPassword
          })

          sendJSON(200, { message: '✅ You have successfully signed up!!!' });

        } catch (err) {
          sendJSON(500, { error: err.message })
        }
     })
  }
  // /POST for sign in 
  else if(req.url=== '/signin' && req.method==='POST'){
    let body = '';
    req.on('data', chunk => body +=chunk.toString());
    req.on('end', async()=>{
      try {
        const { email, password } = JSON.parse(body);
        if(!email || !password) return sendJSON(400, { message: 'Email and password required' })
        
        const user = users.find(u => u.email)
        if(!user) return sendJSON(401, { message: 'Invalid credentials' });

        const isMatched = await bcrypt.compare(password, user.password)
        if(!isMatched) return sendJSON(401, { message: 'Invalid credentials' })

        const token = jwt.sign(
          { email: user.email }, 
          JWT_SECRET, 
          { expiresIn: '1hr' } 
        );

        sendJSON(200, { message: `✅ Welcome back! ${user.name}`, token })

      } catch (err) {
        sendJSON(500, { error: err.message })
      }
    })
  }
  else if(req.url=== '/users' && req.method==='GET'){
    sendJSON(201, users)
  }

  else{
    sendJSON(404, { message: 'Route not found' })
  }
})
server.listen(PORT, ()=>{
  console.log(`This is serving from port: http://localhost:${PORT}`)
})