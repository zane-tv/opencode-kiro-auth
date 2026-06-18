import { CodeWhispererStreamingClient } from '@aws/codewhisperer-streaming-client'
import { KIRO_CONSTANTS } from '../constants.js'
import type { KiroAuthDetails } from './types'

const clientCache = new Map<string, { client: CodeWhispererStreamingClient; token: string }>()
const KIRO_CLI_MAX_ATTEMPTS = 3

export function createSdkClient(
  auth: KiroAuthDetails,
  region: string
): CodeWhispererStreamingClient {
  const cacheKey = `${region}:${auth.email || 'default'}`
  const cached = clientCache.get(cacheKey)

  if (cached && cached.token === auth.access) {
    return cached.client
  }

  const token = auth.access
  const client = new CodeWhispererStreamingClient({
    region,
    endpoint: `https://q.${region}.amazonaws.com`,
    token: () => Promise.resolve({ token }),
    maxAttempts: KIRO_CLI_MAX_ATTEMPTS,
    retryMode: 'standard',
    customUserAgent: [[KIRO_CONSTANTS.USER_AGENT]]
  })

  client.middlewareStack.add(
    (next: any) => async (args: any) => {
      args.request.headers['x-amzn-kiro-agent-mode'] = 'vibe'
      if (auth.authMethod === 'external-idp') {
        args.request.headers.TokenType = 'EXTERNAL_IDP'
      }
      return next(args)
    },
    { step: 'build', name: 'addKiroHeaders' }
  )

  clientCache.set(cacheKey, { client, token })
  return client
}

export function clearSdkClientCache(): void {
  for (const entry of clientCache.values()) {
    entry.client.destroy()
  }
  clientCache.clear()
}
