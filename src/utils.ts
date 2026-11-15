import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/**
 * Generate a secure type safe UID with specified length.
 * Rewrite of https://github.com/crypto-utils/uid-safe
 * @param {Number} length UID length
 * @returns {String} Type safe UID
 */
export function typeSafeUID(length: number): string {
  return randomBytes(length).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}

/**
 * Generate a cryptographically secure base62 salt with specified length.
 * @param {Number} length Salt length
 * @returns {String} Salt
 */
export function randomBase62(length: number): string {
  const availableCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const alphabetLength = availableCharacters.length
  const maxUniformValue = 256 - (256 % alphabetLength)
  let salt = ''

  while (salt.length < length) {
    const byte = randomBytes(1)[0]
    if (byte >= maxUniformValue) continue
    salt += availableCharacters[byte % alphabetLength]
  }

  return salt
}

/**
 * Ensure a token candidate is a single, well-formed string.
 * Arrays, repeated fields and non-string values are rejected.
 * @param {unknown} value Raw token candidate coming from a single source
 * @returns {String | undefined} The token when valid, otherwise undefined
 */
export function asSingleToken(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }

  return value
}

/**
 * Create a SHA1 hash from specified string
 * Rewrite of a function from https://github.com/pillarjs/csrf
 * @param {String} str Dirty string
 * @returns {String} Hashed string
 */
export function hash(str: string): string {
  return createHash('sha256')
    .update(str, 'ascii')
    .digest('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

/**
 * Compare two keys, to check if they have the same creation duration.
 * Rewrite of https://github.com/suryagh/tsscmp
 * @param {String} a Key #1
 * @param {String} b Key #2
 * @returns {Boolean} Whether both keys matches or not
 */
export function timeSafeCompare(a: string, b: string): boolean {
  const key = randomBytes(32)
  const aHMAC = createHmac('sha256', key).update(String(a)).digest()
  const bHMAC = createHmac('sha256', key).update(String(b)).digest()

  return timingSafeEqual(aHMAC, bHMAC)
}
