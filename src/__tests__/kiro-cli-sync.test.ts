import { describe, expect, test } from 'bun:test'
import { decodeRefreshToken, encodeRefreshToken } from '../kiro/auth.js'
import { mergeAccounts } from '../plugin/storage/locked-operations.js'
import {
  getKiroCliTokenAuthMethod,
  shouldSkipKiroCliAccountImport
} from '../plugin/sync/kiro-cli.js'
import { getStaleKiroCliAccountIds } from '../plugin/sync/stale-accounts.js'
import { refreshAccessToken } from '../plugin/token.js'
import type { ManagedAccount } from '../plugin/types.js'

function account(overrides: Partial<ManagedAccount> = {}): ManagedAccount {
  return {
    id: 'account-id',
    email: 'user@example.com',
    authMethod: 'idc',
    region: 'us-east-1',
    clientId: 'client-current',
    clientSecret: 'secret',
    profileArn: 'arn:aws:codewhisperer:us-east-1:123:profile/current',
    refreshToken: 'refresh',
    accessToken: 'access',
    expiresAt: Date.now() + 3600000,
    rateLimitResetTime: 0,
    isHealthy: true,
    failCount: 0,
    ...overrides
  }
}

describe('Kiro CLI account sync', () => {
  test('healthy CLI credentials recover an account with a previous permanent refresh error', () => {
    const existing = account({
      isHealthy: false,
      failCount: 10,
      unhealthyReason: 'Refresh failed: HTTP_401',
      recoveryTime: Date.now() + 3600000,
      accessToken: 'stale-access'
    })

    const incoming = account({
      accessToken: 'fresh-access',
      isHealthy: true,
      failCount: 0,
      unhealthyReason: undefined,
      recoveryTime: undefined
    })

    const merged = mergeAccounts([existing], [incoming])[0]!

    expect(merged.isHealthy).toBe(true)
    expect(merged.failCount).toBe(0)
    expect(merged.unhealthyReason).toBeUndefined()
    expect(merged.recoveryTime).toBeUndefined()
    expect(merged.accessToken).toBe('fresh-access')
  })

  test('deactivates stale cached CLI account variants after a successful CLI import', () => {
    const synced = {
      id: 'current-id',
      email: 'user@example.com',
      authMethod: 'idc' as const,
      clientId: 'client-current',
      profileArn: 'arn:aws:codewhisperer:us-east-1:123:profile/current'
    }

    const staleSameProfile = {
      id: 'old-id',
      email: 'user@example.com',
      auth_method: 'idc',
      client_id: 'client-old',
      profile_arn: synced.profileArn,
      last_sync: Date.now() - 1000
    }
    const stalePreviouslySynced = {
      id: 'old-cli-synced-id',
      email: 'old@example.com',
      auth_method: 'idc',
      client_id: 'client-old-2',
      profile_arn: 'arn:aws:codewhisperer:us-east-1:123:profile/old',
      last_sync: Date.now() - 1000
    }
    const manualOtherAccount = {
      id: 'manual-id',
      email: 'other@example.com',
      auth_method: 'desktop',
      client_id: 'manual-client',
      profile_arn: 'arn:aws:codewhisperer:us-east-1:123:profile/manual',
      last_sync: 0
    }

    expect(
      getStaleKiroCliAccountIds(
        [synced, staleSameProfile, stalePreviouslySynced, manualOtherAccount],
        [synced]
      )
    ).toEqual(['old-id', 'old-cli-synced-id'])
  })

  test('classifies external IdP CLI tokens separately from desktop tokens', () => {
    expect(getKiroCliTokenAuthMethod('kirocli:external-idp:token', {})).toBe('external-idp')
    expect(
      getKiroCliTokenAuthMethod('kirocli:any:token', { token_endpoint: 'https://idp/token' })
    ).toBe('external-idp')
    expect(getKiroCliTokenAuthMethod('kirocli:odic:token', {})).toBe('idc')
    expect(getKiroCliTokenAuthMethod('kirocli:social:token', {})).toBe('desktop')
  })

  test('imports CLI token when cached token differs even if cached expiry is later', () => {
    const now = Date.now()

    expect(
      shouldSkipKiroCliAccountImport(
        {
          is_healthy: 1,
          access_token: 'cached-access',
          expires_at: now + 7200000
        },
        'cli-access',
        now + 3600000,
        now
      )
    ).toBe(false)

    expect(
      shouldSkipKiroCliAccountImport(
        {
          is_healthy: 1,
          access_token: 'cli-access',
          expires_at: now + 7200000
        },
        'cli-access',
        now + 3600000,
        now
      )
    ).toBe(true)
  })

  test('deactivates previous desktop placeholder when external IdP replaces it', () => {
    const synced = {
      id: 'current-external-idp',
      email: 'user@example.com',
      authMethod: 'external-idp' as const,
      clientId: 'client-current',
      profileArn: 'arn:aws:codewhisperer:us-east-1:123:profile/current'
    }

    const staleDesktopPlaceholder = {
      id: 'old-desktop-placeholder',
      email: 'desktop-placeholder+abc@awsapps.local',
      auth_method: 'desktop',
      client_id: synced.clientId,
      profile_arn: null,
      last_sync: Date.now() - 1000
    }

    expect(getStaleKiroCliAccountIds([synced, staleDesktopPlaceholder], [synced])).toEqual([
      'old-desktop-placeholder'
    ])
  })

  test('round-trips external IdP refresh token metadata', () => {
    const encoded = encodeRefreshToken({
      refreshToken: 'refresh-token',
      clientId: 'client-id',
      tokenEndpoint: 'https://login.example.com/oauth2/v2.0/token',
      authMethod: 'external-idp'
    })

    expect(decodeRefreshToken(encoded)).toEqual({
      refreshToken: 'refresh-token',
      clientId: 'client-id',
      tokenEndpoint: 'https://login.example.com/oauth2/v2.0/token',
      authMethod: 'external-idp'
    })
  })

  test('refreshes external IdP tokens through the stored token endpoint', async () => {
    const originalFetch = globalThis.fetch
    const calls: Array<{ url: string; init: RequestInit }> = []

    globalThis.fetch = (async (url: string, init: RequestInit) => {
      calls.push({ url, init })
      return new Response(
        JSON.stringify({
          access_token: 'new-access',
          refresh_token: 'new-refresh',
          expires_in: 120
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }) as typeof fetch

    try {
      const tokenEndpoint = 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token'
      const refreshed = await refreshAccessToken({
        refresh: encodeRefreshToken({
          refreshToken: 'old-refresh',
          clientId: 'client-id',
          tokenEndpoint,
          authMethod: 'external-idp'
        }),
        access: 'old-access',
        expires: 0,
        authMethod: 'external-idp',
        region: 'us-east-1',
        profileArn: 'arn:aws:codewhisperer:us-east-1:123:profile/current',
        clientId: 'client-id',
        tokenEndpoint
      })

      expect(calls).toHaveLength(1)
      expect(calls[0]!.url).toBe(tokenEndpoint)
      expect(calls[0]!.init.headers).toMatchObject({
        'Content-Type': 'application/x-www-form-urlencoded'
      })
      expect(String(calls[0]!.init.body)).toContain('grant_type=refresh_token')
      expect(String(calls[0]!.init.body)).toContain('refresh_token=old-refresh')
      expect(String(calls[0]!.init.body)).toContain('client_id=client-id')
      expect(String(calls[0]!.init.body)).toContain(
        'scope=client-id%2Fcodewhisperer%3Aconversations+client-id%2Fcodewhisperer%3Acompletions+offline_access'
      )
      expect(refreshed.access).toBe('new-access')
      expect(decodeRefreshToken(refreshed.refresh)).toMatchObject({
        refreshToken: 'new-refresh',
        clientId: 'client-id',
        tokenEndpoint,
        authMethod: 'external-idp'
      })
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
