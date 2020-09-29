const crypto = require('crypto');

function encodeRFC3986(uri) {
  return encodeURIComponent(uri).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function encodeObjectRFC3986(object) {
  return Object.keys(object).reduce((encoded, key) => {
    encoded[encodeRFC3986(key)] = encodeRFC3986(object[key]);

    return encoded;
  }, {});
}

function generateSignature({
  method,
  url,
  body,
  query,
  oauth_consumer_key,
  oauth_consumer_secret,
  oauth_nonce,
  oauth_signature_method,
  oauth_timestamp,
  oauth_token,
  oauth_token_secret,
  oauth_version,
}) {
  const parameters = {
    ...encodeObjectRFC3986(body),
    ...encodeObjectRFC3986(query),
  };

  parameters[encodeRFC3986('oauth_consumer_key')] = encodeRFC3986(oauth_consumer_key);
  parameters[encodeRFC3986('oauth_nonce')] = encodeRFC3986(oauth_nonce);
  parameters[encodeRFC3986('oauth_signature_method')] = encodeRFC3986(oauth_signature_method);
  parameters[encodeRFC3986('oauth_timestamp')] = oauth_timestamp;
  parameters[encodeRFC3986('oauth_token')] = encodeRFC3986(oauth_token);
  parameters[encodeRFC3986('oauth_version')] = encodeRFC3986(oauth_version);

  const parametersString = Object.keys(parameters)
    .sort((a, b) => a.localeCompare(b))
    .map((k) => `${k}=${parameters[k]}`)
    .join('&');

  const signatureString = `${method}&${encodeRFC3986(url)}&${encodeRFC3986(parametersString)}`;
  const signingKey = `${encodeRFC3986(oauth_consumer_secret)}&${encodeRFC3986(oauth_token_secret)}`;

  return crypto.createHmac('sha1', signingKey).update(signatureString).digest('base64');
}

function generateOAuthHeader({
  method,
  url,
  body,
  query,
  oauth_consumer_key,
  oauth_consumer_secret,
  oauth_nonce,
  oauth_signature_method,
  oauth_timestamp,
  oauth_token,
  oauth_token_secret,
  oauth_version,
}) {
  const oauth_signature = decodeURIComponent(
    encodeRFC3986(
      generateSignature({
        method,
        url,
        body,
        query,
        oauth_consumer_key,
        oauth_consumer_secret,
        oauth_nonce,
        oauth_signature_method,
        oauth_timestamp,
        oauth_token,
        oauth_token_secret,
        oauth_version,
      })
    )
  );

  const parameters = {};

  parameters[encodeRFC3986('oauth_consumer_key')] = encodeRFC3986(oauth_consumer_key);
  parameters[encodeRFC3986('oauth_nonce')] = encodeRFC3986(oauth_nonce);
  parameters[encodeRFC3986('oauth_signature')] = encodeRFC3986(oauth_signature);
  parameters[encodeRFC3986('oauth_signature_method')] = encodeRFC3986(oauth_signature_method);
  parameters[encodeRFC3986('oauth_timestamp')] = oauth_timestamp;
  parameters[encodeRFC3986('oauth_token')] = encodeRFC3986(oauth_token);
  parameters[encodeRFC3986('oauth_version')] = encodeRFC3986(oauth_version);

  const parametersString = Object.keys(parameters)
    .sort((a, b) => a.localeCompare(b))
    .map((k) => `${k}="${parameters[k]}"`)
    .join(', ');

  return `OAuth ${parametersString}`;
}

function createNonce() {
  return crypto.randomBytes(32).toString('base64').replace(/\W/g, '');
}
