// Browser-only shim for @cloudflare/voprf-ts internal build settings.
//
// The upstream package defaults to the SJCL backend, which includes a Node-only
// `require('crypto')` branch. Vite warns about this during browser builds.
//
// We alias the internal buildSettings module to this file so the default crypto
// provider is noble (pure JS + WebCrypto-friendly), preventing SJCL from being
// pulled into the client bundle.

import { CryptoNoble } from '@cloudflare/voprf-ts/crypto-noble'

export const CRYPTO_PROVIDER_ARG_REQUIRED = false
export const DEFAULT_CRYPTO_PROVIDER = CryptoNoble
