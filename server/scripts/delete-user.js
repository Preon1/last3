#!/usr/bin/env node
import readline from 'node:readline'
import process from 'node:process'

function usage(exitCode = 0) {
  const msg = `Usage:
  node scripts/delete-user.js (--user-id <uuid> | --name-token <token> | --username <name>) [--yes] [--dry-run]

Options:
  --user-id        User ID (UUID) to delete (exact match)
  --name-token     VOPRF name token to delete (exact match)
  --username, -u   Username to delete (requires VOPRF_PRIVATE_KEY_B64U)
  --yes, -y        Skip confirmation prompt
  --dry-run        Print what would be deleted, but do not modify DB
  --help, -h       Show this help

Notes:
  - This performs the same DB deletion as Settings → Delete account (authDeleteAccount).
  - If the main server process is running, any in-memory session/websocket state for the user may persist until restart.
`
  // eslint-disable-next-line no-console
  console.log(msg)
  process.exit(exitCode)
}

function parseArgs(argv) {
  const out = { userId: null, nameToken: null, username: null, yes: false, dryRun: false, help: false }

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--help' || a === '-h') out.help = true
    else if (a === '--yes' || a === '-y') out.yes = true
    else if (a === '--dry-run') out.dryRun = true
    else if (a === '--user-id') {
      out.userId = String(argv[i + 1] ?? '')
      i++
    }
    else if (a === '--name-token') {
      out.nameToken = String(argv[i + 1] ?? '')
      i++
    }
    else if (a === '--username' || a === '-u') {
      out.username = String(argv[i + 1] ?? '')
      i++
    } else if (!a.startsWith('-') && !out.username) {
      // Allow positional username as convenience
      out.username = String(a)
    } else {
      return { ...out, help: true }
    }
  }

  return out
}

function canonicalizeUsername(input) {
  return String(input ?? '').normalize('NFKC').trim().toLowerCase()
}

async function deriveNameTokenFromUsername(username) {
  const VOPRF_PRIVATE_KEY_B64U = String(process.env.VOPRF_PRIVATE_KEY_B64U ?? '').trim()
  if (!VOPRF_PRIVATE_KEY_B64U) {
    throw new Error('VOPRF_PRIVATE_KEY_B64U is not set; cannot derive name-token from username')
  }

  const { Oprf, VOPRFClient, VOPRFServer, generatePublicKey } = await import('@cloudflare/voprf-ts')

  const suite = Oprf.Suite.P256_SHA256
  const privateKey = new Uint8Array(Buffer.from(VOPRF_PRIVATE_KEY_B64U, 'base64url'))
  const publicKey = generatePublicKey(suite, privateKey)
  const server = new VOPRFServer(suite, privateKey)
  const client = new VOPRFClient(suite, publicKey)

  const inputCanon = canonicalizeUsername(username)
  if (!inputCanon) throw new Error('username required')

  // Domain separation to match the client: user tokens are derived from `u:<canonical>`.
  const prefixed = `u:${inputCanon}`
  const u8 = new TextEncoder().encode(prefixed)

  const [finData, evalReq] = await client.blind([u8])
  const evaluation = await server.blindEvaluate(evalReq)
  const out = await client.finalize(finData, evaluation)

  const tokenBytes = out?.[0]
  if (!(tokenBytes instanceof Uint8Array) || !tokenBytes.length) throw new Error('VOPRF finalize failed')
  return Buffer.from(tokenBytes).toString('base64url')
}

async function promptConfirm(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  try {
    const answer = await new Promise((resolve) => rl.question(question, resolve))
    return String(answer).trim().toLowerCase() === 'yes'
  } finally {
    rl.close()
  }
}

async function main() {
  const args = parseArgs(process.argv)
  if (args.help) usage(0)

  const userIdArg = String(args.userId ?? '').trim()
  const nameTokenArg = String(args.nameToken ?? '').trim()
  const usernameArg = String(args.username ?? '').trim()
  if (!userIdArg && !nameTokenArg && !usernameArg) usage(1)

  const { initDatabase, query, getPool } = await import('../db.js')
  const { authDeleteAccount } = await import('../authDb.js')

  initDatabase()

  let r
  let displayTarget = ''
  if (userIdArg) {
    displayTarget = `userId=${userIdArg}`
    r = await query('SELECT id, name_token, remove_date FROM users WHERE id = $1', [userIdArg])
  } else {
    const token = nameTokenArg || await deriveNameTokenFromUsername(usernameArg)
    displayTarget = nameTokenArg ? `nameToken=${token}` : `username=${usernameArg} nameToken=${token}`
    r = await query('SELECT id, name_token, remove_date FROM users WHERE name_token = $1', [token])
  }

  if (!r.rowCount) {
    // eslint-disable-next-line no-console
    console.error(`User not found: ${displayTarget}`)
    process.exit(2)
  }

  const row = r.rows[0]
  const userId = String(row.id)

  // eslint-disable-next-line no-console
  console.log(`Target: id=${userId} name_token=${String(row.name_token ?? '')} remove_date=${row.remove_date}`)

  if (args.dryRun) {
    // eslint-disable-next-line no-console
    console.log('[dry-run] Would delete user and cascade related rows; would also prune orphaned chats.')
    process.exit(0)
  }

  if (!args.yes) {
    const ok = await promptConfirm(`Type 'yes' to permanently delete this user: `)
    if (!ok) {
      // eslint-disable-next-line no-console
      console.log('Aborted.')
      process.exit(0)
    }
  }

  const res = await authDeleteAccount(userId)

  // eslint-disable-next-line no-console
  console.log(`Deleted users: ${res.deletedUsers}; deleted chats: ${res.deletedChats}`)

  // Close DB pool so the process exits promptly.
  try {
    await getPool().end()
  } catch {
    // ignore
  }
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error('Failed to delete user:', e?.message ?? e)
  process.exit(1)
})
