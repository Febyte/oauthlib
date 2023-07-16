import base64url from 'base64url'
import { v4 as uuid } from 'uuid'
import crypto from 'crypto'
import axios from 'axios'

function formEncodeObject(obj: any) {
    const payloadKeys = Object.keys(obj)
    const kvpMap = payloadKeys.map((key, _i, _a) => {
        const value = obj[key]

        const kvp = `${encodeURI(key)}=${encodeURI(value)}`
        return kvp
    })
    const payloadEncoded = kvpMap.join('&')

    return payloadEncoded
}

export function buildHeaderAndPayload(clientId: string, tokenEndpointUri: string): string {
    const header = {
        alg: 'RS256',
        typ: 'JWT'
    }

    const headerJson = JSON.stringify(header)
    const headerEncoded = base64url.default.encode(headerJson, 'utf8')

    const unixNow = Math.floor(new Date().getTime() / 1000)
    const notBefore = unixNow - 5 * 60
    const expiresAt = unixNow + 5 * 60

    const payload = {
        sub: clientId,
        jti: uuid(),
        nbf: notBefore,
        exp: expiresAt,
        iss: clientId,
        aud: tokenEndpointUri
    }

    const payloadJson = JSON.stringify(payload)
    const payloadEncoded = base64url.default.encode(payloadJson, 'utf8')

    const signaturePayloadText = `${headerEncoded}.${payloadEncoded}`
    return signaturePayloadText
}

export function buildClientAssertation(clientId: string, tokenEndpointUri: string, pemKey: string) {
    const signaturePayloadText = buildHeaderAndPayload(clientId, tokenEndpointUri)
    const privateKey = crypto.createPrivateKey(pemKey)

    const sign = crypto.createSign('RSA-SHA256')
    sign.update(signaturePayloadText)
    const signature = sign.sign(privateKey, 'base64url')

    const clientAssertation = `${signaturePayloadText}.${signature}`
    return clientAssertation
}

export function getAccessToken(clientId: string, tokenEndpointUri: string, pemKey: string, tokenCallback: (token: any) => void): void {
    const clientAssertation = buildClientAssertation(clientId, tokenEndpointUri, pemKey)
    
    const payload: { [key: string]: string } = {
        client_id: clientId,
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: clientAssertation,
    }

    const payloadEncoded = formEncodeObject(payload)

    axios.post(tokenEndpointUri, payloadEncoded)
        .then(resp => tokenCallback(resp.data))
}

export function exchangeToken(initialToken: any, requestedClientId: string, requestedSubject: string, tokenEndpointUri: string, pemKey: string, tokenCallback: (token: any) => void): void {
    const clientAssertation = buildClientAssertation(requestedClientId, tokenEndpointUri, pemKey)

    const payload: { [key: string]: string } = {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        scope: 'openid',
        subject_token: initialToken.access_token,
        requested_subject: requestedSubject,
        client_id: requestedClientId,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: clientAssertation
    }

    const payloadEncoded = formEncodeObject(payload)

    axios.post(tokenEndpointUri, payloadEncoded)
        .then(resp => tokenCallback(resp.data))
}
