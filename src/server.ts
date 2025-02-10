import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

dotenv.config()

const app = express()
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  }),
)
app.use(express.json())

const users: { email: string; password: string }[] = []

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" })
    }
    const existingUser = users.find((u) => u.email === email)
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" })
    }
    const hashedPassword = await bcrypt.hash(password, 10)
    users.push({ email, password: hashedPassword })
    const token = jwt.sign({ email }, process.env.JWT_SECRET as string)
    res.json({ token, message: "Thank You For Signing Up With Hackerug06 Technologies" })
  } catch (error) {
    console.error("Signup error:", error)
    res.status(500).json({ error: "Internal server error", details: error.message })
  }
})

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body
    const user = users.find((u) => u.email === email)
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ email }, process.env.JWT_SECRET as string)
      res.json({ token })
    } else {
      res.status(400).json({ error: "Invalid credentials" })
    }
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ error: "Internal server error", details: error.message })
  }
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))

  
