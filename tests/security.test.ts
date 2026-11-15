import { assert, describe, it } from 'vitest'
import { onTestFinished } from 'vitest'
import { Tokens } from '../src/token'
import { randomBase62 } from '../src/utils'
import { initApp } from './helper'

describe('single-source token extraction', () => {
  it('rejects a token present in both body and a header (403)', async () => {
    const { fetch, server } = initApp({ middleware: 'cookie', parser: 'json' })
    onTestFinished(() => {
      server.close()
    })

    const setup = await fetch('/')
    const { token } = await setup.json()

    const response = await fetch('/', {
      method: 'post',
      body: JSON.stringify({ _csrf: token }),
      headers: {
        cookie: setup.headers.get('set-cookie') ?? '',
        'content-type': 'application/json',
        'x-csrf-token': token
      }
    })

    assert.equal(response.status, 403)
    assert.equal(await response.text(), 'invalid csrf token')
  })

  it('rejects a token present in both query and a header (403)', async () => {
    const { fetch, server } = initApp({ middleware: 'session', options: { middleware: 'session' } })
    onTestFinished(() => {
      server.close()
    })

    const setup = await fetch('/')
    const { token } = await setup.json()

    const response = await fetch(`/?_csrf=${encodeURIComponent(token)}`, {
      method: 'post',
      headers: {
        cookie: setup.headers.get('set-cookie') ?? '',
        'x-xsrf-token': token
      }
    })

    assert.equal(response.status, 403)
  })

  it('rejects repeated query parameters (403)', async () => {
    const { fetch, server } = initApp({ middleware: 'cookie' })
    onTestFinished(() => {
      server.close()
    })

    const setup = await fetch('/')
    const { token } = await setup.json()

    const response = await fetch(`/?_csrf=${encodeURIComponent(token)}&_csrf=${encodeURIComponent(token)}`, {
      method: 'post',
      headers: {
        cookie: setup.headers.get('set-cookie') ?? ''
      }
    })

    assert.equal(response.status, 403)
  })

  it('rejects multiple header aliases carrying a token (403)', async () => {
    const { fetch, server } = initApp({ middleware: 'cookie' })
    onTestFinished(() => {
      server.close()
    })

    const setup = await fetch('/')
    const { token } = await setup.json()

    const response = await fetch('/', {
      method: 'post',
      headers: {
        cookie: setup.headers.get('set-cookie') ?? '',
        'csrf-token': token,
        'x-csrf-token': token
      }
    })

    assert.equal(response.status, 403)
  })

  it('rejects comma-joined repeated header values (403)', async () => {
    const { fetch, server } = initApp({ middleware: 'cookie' })
    onTestFinished(() => {
      server.close()
    })

    const setup = await fetch('/')
    const { token } = await setup.json()

    const response = await fetch('/', {
      method: 'post',
      headers: {
        cookie: setup.headers.get('set-cookie') ?? '',
        'x-csrf-token': `${token}, ${token}`
      }
    })

    assert.equal(response.status, 403)
  })
})

describe('Tokens.verify() input hardening', () => {
  const tokens = new Tokens({ saltLength: 8, secretLength: 18 })
  const secret = tokens.secret()
  const token = tokens.create(secret)

  it('accepts a valid single string token', () => {
    assert.equal(tokens.verify(secret, token), true)
  })

  it('rejects array tokens instead of silently joining them', () => {
    const [salt, hash] = token.split('-')
    assert.equal(tokens.verify(secret, [salt, '-', hash]), false)
  })

  it('rejects non-string tokens', () => {
    assert.equal(tokens.verify(secret, undefined), false)
    assert.equal(tokens.verify(secret, 123), false)
    assert.equal(tokens.verify(secret, { token }), false)
  })

  it('rejects malformed tokens without a salt or hash', () => {
    assert.equal(tokens.verify(secret, 'no-separator'), false)
    assert.equal(tokens.verify(secret, '-missing-salt'), false)
    assert.equal(tokens.verify(secret, 'missing-hash-'), false)
  })
})

describe('randomBase62() salt generation', () => {
  it('uses a CSPRNG and only emits base62 characters', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const salts = Array.from({ length: 50 }, () => randomBase62(32))

    for (const salt of salts) {
      assert.equal(salt.length, 32)
      assert.match(salt, /^[A-Za-z0-9]+$/)
      for (const character of salt) {
        assert.ok(alphabet.includes(character))
      }
    }
  })

  it('produces distinct salts across calls', () => {
    assert.notEqual(randomBase62(32), randomBase62(32))
  })
})
