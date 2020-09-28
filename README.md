# Twitter Create Signature, Authorize Request utilities in JavaScript and TypeScript

use `generateOAuthHeader()` to generate the OAuth header, use `createNonce()` for the `oauth_nonce` parameter, `Math.floor(new Date().getTime() / 1000)` for the `oauth_timestamp` parameter, `HMAC-SHA1` for the `oauth_signature_method` parameter, `1.0` for the `oauth_version` parameter, you can pass in request body or query params through the `body` or `query` parameters respectively, then you just need to provide your `oauth_consumer_key`, `oauth_consumer_secret`, `oauth_token` and `oauth_token_secret`
