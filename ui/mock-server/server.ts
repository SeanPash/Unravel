import { createServer } from 'http'
import { WebSocketServer, WebSocket } from 'ws'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(__dirname, 'fixtures', 'chain-phishing.json')
const PORT = 8080
const WS_PATH = '/ws'
// Delay between replayed messages in milliseconds
const MSG_DELAY_MS = 1_500

type Message = { type: string; payload: unknown }

function loadFixture(): Message[] {
  const raw = readFileSync(FIXTURE_PATH, 'utf-8')
  return JSON.parse(raw) as Message[]
}

async function replayToClient(ws: WebSocket, messages: Message[]): Promise<void> {
  for (const msg of messages) {
    if (ws.readyState !== WebSocket.OPEN) break
    ws.send(JSON.stringify(msg))
    console.log(`  -> sent ${msg.type}`)
    await new Promise<void>((resolve) => setTimeout(resolve, MSG_DELAY_MS))
  }
}

const messages = loadFixture()
console.log(`Loaded ${messages.length} messages from fixture`)

const httpServer = createServer((_req, res) => {
  res.writeHead(404)
  res.end()
})

const wss = new WebSocketServer({ server: httpServer, path: WS_PATH })

wss.on('connection', (ws, req) => {
  console.log(`Client connected from ${req.socket.remoteAddress}`)
  replayToClient(ws, messages).then(() => {
    console.log('Replay complete')
  }).catch((err: unknown) => {
    console.error('Replay error:', err)
  })

  ws.on('close', () => {
    console.log('Client disconnected')
  })
})

httpServer.listen(PORT, () => {
  console.log(`Mock engine server listening on ws://localhost:${PORT}${WS_PATH}`)
  console.log(`Replaying ${messages.length} messages with ${MSG_DELAY_MS}ms delay between each`)
  console.log('Start the UI dev server and connect to see the full kill chain.')
})
