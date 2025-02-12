import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"
import nodemailer from "nodemailer"
import { parsePhoneNumber } from "libphonenumber-js"
import crypto from "crypto"
import { SmsClient, type SmsMessage } from "@infobip-api/sdk"

dotenv.config()

const app = express()
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  }),
)
app.use(express.json())

interface User {
  email?: string
  phoneNumber?: string
  password: string
  verified: boolean
  verificationToken?: string
}

const users: User[] = []

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 587,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
})

const smsClient = new SmsClient({
  baseUrl: process.env.INFOBIP_BASE_URL,
  apiKey: process.env.INFOBIP_API_KEY,
})

app.post("/signup", async (req, res) => {
  try {
    const { email, phoneNumber, password } = req.body
    if ((!email && !phoneNumber) || !password) {
      return res.status(400).json({ error: "Email or phone number, and password are required" })
    }

    let identifier = email
    let isEmail = true

    if (phoneNumber) {
      const parsedPhoneNumber = parsePhoneNumber(phoneNumber)
      if (!parsedPhoneNumber || !parsedPhoneNumber.isValid()) {
        return res.status(400).json({ error: "Invalid phone number" })
      }
      identifier = parsedPhoneNumber.format("E.164")
      isEmail = false
    }

    const existingUser = users.find((u) => u.email === identifier || u.phoneNumber === identifier)
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const verificationToken = crypto.randomBytes(20).toString("hex")

    const newUser: User = {
      password: hashedPassword,
      verified: false,
      verificationToken,
    }

    if (isEmail) {
      newUser.email = identifier
    } else {
      newUser.phoneNumber = identifier
    }

    users.push(newUser)

    if (isEmail) {
      const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`

      await transporter.sendMail({
        from: process.env.SMTP_FROM,
        to: identifier,
        subject: "Verify your email for Hackerug06 Technologies",
        html: `Please click this link to verify your email: <a href="${verificationLink}">${verificationLink}</a>`,
      })

      res.json({ message: "Please check your email to verify your account" })
    } else {
      const verificationCode = verificationToken.slice(0, 6)

      const smsMessage: SmsMessage = {
        destinations: [{ to: identifier }],
        text: `Your Hackerug06 Technologies verification code is: ${verificationCode}`,
        from: process.env.INFOBIP_SENDER_ID,
      }

      await smsClient.send(smsMessage)

      res.json({ message: "Please check your phone for the verification code", verificationToken })
    }
  } catch (error: any) {
    console.error("Signup error:", error)
    res.status(500).json({ error: "Internal server error", details: error.message })
  }
})

app.post("/verify", (req, res) => {
  const { token, code } = req.body
  const user = users.find((u) => u.verificationToken === token)

  if (user && user.verificationToken) {
    if (code && code !== user.verificationToken.slice(0, 6)) {
      return res.status(400).json({ error: "Invalid verification code" })
    }
    user.verified = true
    user.verificationToken = undefined
    res.json({ message: "Account verified successfully. You can now log in." })
  } else {
    res.status(400).json({ error: "Invalid verification token" })
  }
})

app.post("/login", async (req, res) => {
  try {
    const { identifier, password } = req.body
    const user = users.find((u) => u.email === identifier || u.phoneNumber === identifier)
    if (user && (await bcrypt.compare(password, user.password))) {
      if (!user.verified) {
        return res.status(403).json({ error: "Please verify your account before logging in" })
      }
      const token = jwt.sign({ identifier }, process.env.JWT_SECRET as string)
      res.json({ token })
    } else {
      res.status(400).json({ error: "Invalid credentials" })
    }
  } catch (error: any) {
    console.error("Login error:", error)
    res.status(500).json({ error: "Internal server error", details: error.message })
  }
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))

        
