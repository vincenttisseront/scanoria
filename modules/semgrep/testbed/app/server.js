// Banc d'essai Scanoria : code volontairement vulnérable, jamais exécuté.
const express = require('express')
const app = express()

app.get('/user', async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(rows)
})

app.get('/ok', async (req, res) => {
  res.json(await db.query('SELECT 1 WHERE $1 = $1', [req.query.name]))
})
