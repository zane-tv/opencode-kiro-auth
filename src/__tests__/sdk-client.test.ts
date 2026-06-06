import { describe, expect, test } from 'bun:test'
import { clearSdkClientCache, createSdkClient } from '../plugin/sdk-client'
import type { KiroAuthDetails } from '../plugin/types'

function auth(): KiroAuthDetails {
  return {
    refresh: 'refresh-token',
    access: 'access-token',
    expires: Date.now() + 3600000,
    authMethod: 'idc',
    region: 'us-east-1',
    email: 'user@example.com'
  }
}

describe('SDK client', () => {
  test('uses Kiro CLI-style standard SDK retries for throttling', async () => {
    clearSdkClientCache()

    const client = createSdkClient(auth(), 'us-east-1')

    expect(await client.config.maxAttempts()).toBe(3)
    const retryMode = client.config.retryMode
    expect(typeof retryMode === 'function' ? await retryMode() : retryMode).toBe('standard')

    clearSdkClientCache()
  })
})
