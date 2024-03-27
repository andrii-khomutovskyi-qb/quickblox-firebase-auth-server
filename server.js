const fs = require('fs')
const https = require('https')
const crypto = require('crypto')
const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const axios = require('axios').default

require('dotenv').config()

const app = express()

app.use(cors())
app.use(bodyParser.json())

const httpsAgent = new https.Agent({
  rejectUnauthorized: false,
})

const signMessage = (message) => {
  const sessionMsg = Object.keys(message)
    .map((val) => {
      if (typeof message[val] === 'object') {
        return Object.keys(message[val])
          .map((val1) => {
            return `${val}[${val1}]=${message[val][val1]}`
          })
          .sort()
          .join('&')
      }

      return `${val}=${message[val]}`
    })
    .sort()
    .join('&')

  const signedMessage = crypto
    .createHmac('sha256', process.env.QUICKBLOX_AUTH_SECRET)
    .update(sessionMsg)
    .digest('hex')
    .toString()

  return signedMessage
}

const generateAuthMsgWithFirebase = (access_token) => {
  return {
    application_id: process.env.QUICKBLOX_APP_ID,
    auth_key: process.env.QUICKBLOX_AUTH_KEY,
    nonce: Math.floor(Math.random() * 10000),
    timestamp: Math.floor(Date.now() / 1000),
    provider: 'firebase_phone',
    firebase_phone: {
      access_token,
      project_id: process.env.FIREBASE_PROJECT_ID,
    },
  }
}

app.post('/session/phone', async (req, res) => {
  try {
    const { access_token } = req.body

    const message = generateAuthMsgWithFirebase(access_token)
    const signedMessage = signMessage(message)

    const {
      data: { session },
    } = await axios.post(
      'session.json',
      {
        signature: signedMessage,
        ...message,
      },
      {
        baseURL: process.env.QUICKBLOX_API_URL,
        headers: {
          'Content-Type': 'application/json',
        },
        httpsAgent,
      },
    )

    res.status(201).send({
      session,
    })
  } catch (error) {
    let status = 500
    let errorData = {
      error: {
        message: error.message,
      },
    }

    if ('response' in error) {
      status = error.response.status
      errorData = error.response.data
    }

    res.status(status).send(errorData)
  }
})

const generateAuthMsgWithEmail = (email, password) => {
  return {
    application_id: process.env.QUICKBLOX_APP_ID,
    auth_key: process.env.QUICKBLOX_AUTH_KEY,
    nonce: Math.floor(Math.random() * 10000),
    timestamp: Math.floor(Date.now() / 1000),
    user: {
      email,
      password,
    },
  }
}

app.post('/session/email', async (req, res) => {
  try {
    const { email, password } = req.body

    const message = generateAuthMsgWithEmail(email, password)
    const signedMessage = signMessage(message)

    const {
      data: { session },
    } = await axios.post(
      'session.json',
      {
        signature: signedMessage,
        ...message,
      },
      {
        baseURL: process.env.QUICKBLOX_API_URL,
        headers: {
          'Content-Type': 'application/json',
        },
        httpsAgent,
      },
    )

    res.status(201).send({
      session,
    })
  } catch (error) {
    let status = 500
    let errorData = {
      error: {
        message: error.message,
      },
    }

    if ('response' in error) {
      status = error.response.status
      errorData = error.response.data
    }

    res.status(status).send(errorData)
  }
})

const generateAuthMsgWithLogin = (login, password) => {
  return {
    application_id: process.env.QUICKBLOX_APP_ID,
    auth_key: process.env.QUICKBLOX_AUTH_KEY,
    nonce: Math.floor(Math.random() * 10000),
    timestamp: Math.floor(Date.now() / 1000),
    user: {
      login,
      password,
    },
  }
}

app.post('/session/login', async (req, res) => {
  try {
    const { login, password } = req.body

    const message = generateAuthMsgWithLogin(login, password)
    const signedMessage = signMessage(message)

    const {
      data: { session },
    } = await axios.post(
      'session.json',
      {
        signature: signedMessage,
        ...message,
      },
      {
        baseURL: process.env.QUICKBLOX_API_URL,
        headers: {
          'Content-Type': 'application/json',
        },
        httpsAgent,
      },
    )

    res.status(201).send({
      session,
    })
  } catch (error) {
    let status = 500
    let errorData = {
      error: {
        message: error.message,
      },
    }

    if ('response' in error) {
      status = error.response.status
      errorData = error.response.data
    }

    res.status(status).send(errorData)
  }
})

const runServerListener = () => {
  console.log(`Server is running at port ${process.env.PORT}`)
}

if (process.env.SSL_KEY_FILE && process.env.SSL_CERT_FILE) {
  const certificates = {
    key: fs.readFileSync(process.env.SSL_KEY_FILE),
    cert: fs.readFileSync(process.env.SSL_CERT_FILE),
  }

  https
    .createServer(certificates, app)
    .listen(process.env.PORT, process.env.HOST, runServerListener)
} else {
  app.listen(process.env.PORT, process.env.HOST, runServerListener)
}
