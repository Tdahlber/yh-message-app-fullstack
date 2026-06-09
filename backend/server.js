import "dotenv/config"
import helmet from "helmet"
import cors from "cors"
import express from "express"
import mongoose from "mongoose"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
// RATE LIMITING - Importera express-rate-limit för att begränsa antalet förfrågningar
import rateLimit from "express-rate-limit"
import { Message } from "./models/Message.js"
import { User } from "./models/User.js"
import { authenticateUser } from "./middleware/auth.js"
import "./config/db.js"
import listEndpoints from "express-list-endpoints"

if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is not set in .env")

const PORT = process.env.PORT || "3000"
const app = express()

// ===== RATE LIMITING - TILLAGD SÄKERHETSFUNKTION =====
// Syftet: Skydda servern från missbruk genom att begränsa antalet förfrågningar
// från varje IP-adress

// authLimiter: Strikt gräns för autentiseringsendpunkter (register, login)
// Skyddar mot brute-force-attacker på lösenord
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Tidsfönster: 15 minuter
  max: 5, // Max 5 förfrågningar per tidsfönster per IP
  message: "Too many authentication attempts, please try again later",
  standardHeaders: true, // Inkludera RateLimit-Info i response headers
  legacyHeaders: false, // Inaktivera X-RateLimit-* headers
})

// generalLimiter: Generell gräns för alla andra routes
// Tillämpas globalt för att skydda mot DOS-attacker
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Tidsfönster: 15 minuter
  max: 30, // Max 30 förfrågningar per tidsfönster per IP
  message: "Too many requests, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
})
// ===== SLUT RATE LIMITING =====


app.use(helmet())
app.use(cors({
  origin: "*",
}))
app.use(express.json())
// Tillämpa den generella rate limiter på alla routes
app.use(generalLimiter)

app.get("/", (req, res) => {
  res.send(listEndpoints(app))
})

// RATE LIMITING: authLimiter tillagd för att skydda mot brute-force-attacker
app.post("/register", authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body

    if (!username || username.trim().length < 2) {
      return res.status(400).json({ success: false, message: "Username must be at least 2 characters" })
    }

    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username: username.trim() }]
    })

    if (existingUser) {
      const field = existingUser.email === email.toLowerCase() ? "email" : "username"
      return res.status(400).json({
        success: false,
        message: `A user with this ${field} already exists`
      })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({ username: username.trim(), email, password: hashedPassword })
    await user.save()

    const accessToken = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    )

    res.status(201).json({
      success: true,
      message: "User created successfully",
      response: {
        username: user.username,
        id: user._id,
        accessToken,
      },
    })
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Could not create user",
      error: error,
    })
  }
})

// RATE LIMITING: authLimiter tillagd för att skydda mot brute-force-attacker
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { login, password } = req.body
    const user = await User.findOne({
      $or: [{ username: login }, { email: login }]
    })

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "No account found with that username or email",
        response: null,
      })
    }

    const passwordMatch = await bcrypt.compare(password, user.password)
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Password is incorrect",
        response: null,
      })
    }

    const accessToken = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    )

    res.json({
      success: true,
      message: "Logged in successfully",
      response: {
        username: user.username,
        id: user._id,
        accessToken,
      },
    })
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Something went wrong",
      error: error,
    })
  }
})

const isValidId = (id) => mongoose.Types.ObjectId.isValid(id)

app.get("/messages", async (req, res) => {
  try {
    const messages = await Message.find()
      .sort({ createdAt: "desc" })
      .limit(20)
      .populate("user", "username")
      .exec()
    res.json(messages)
  } catch (error) {
    res.status(500).json({ message: "Could not fetch messages" })
  }
})

app.post("/messages", authenticateUser, async (req, res) => {
  const message = new Message({ message: req.body.message, user: req.user._id })
  try {
    const saved = await message.save()
    res.status(201).json(saved)
  } catch (err) {
    res.status(400).json({ message: "Could not save message", errors: err.errors })
  }
})

app.patch("/messages/:id", authenticateUser, async (req, res) => {
  if (!isValidId(req.params.id)) return res.status(400).json({ error: "Invalid message ID" })
  try {
    const message = await Message.findById(req.params.id)
    if (!message) return res.status(404).json({ error: "Message not found" })

    if (message.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: "You can only edit your own messages" })
    }

    message.message = req.body.editedMessage
    await message.save()
    const updated = await message.populate("user", "username")
    res.json(updated)
  } catch (error) {
    res.status(400).json({ error: "Could not update message" })
  }
})
// Här bör kod ändras till authenticateuser. Vem som helt kan radera vilket meddelande som helst för tillfället utan att vara inloggad.

app.delete("/messages/:id", async (req, res) => {
  if (!isValidId(req.params.id)) return res.status(400).json({ error: "Invalid message ID" })
  try {
    const message = await Message.findById(req.params.id)
    if (!message) return res.status(404).json({ error: "Message not found" })

// if (message.user.toString() !== req.user._id.toString()) {
//   return res.status(403).json({ error: "Ej behörig" })
// } 
 
/*
Security check: ensure authenticateUser is used on this route and verify
that the authenticated user (req.user._id) matches message.user.
If they don't match, return 403 to prevent deleting other users' messages.
After the check, log the event (timestamp, userId, messageId) before calling
await message.deleteOne().
*/
/*
Ownership check: verify that req.user._id is the owner of message.
Return 403 if not the owner. If allowed, save the change and log the update
(timestamp, userId, messageId) for audit purposes.
*/

      await message.deleteOne()
    res.status(204).send()
  } catch (error) {
    res.status(400).json({ error: "Could not delete message" })
  }
})

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`)
})
