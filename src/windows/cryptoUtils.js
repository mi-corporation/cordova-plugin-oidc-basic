/**
 * A partial port of CryptoHelper class from IdentityModel.OidcClient (https://www.nuget.org/packages/IdentityModel.OidcClient/).
 * See https://github.com/IdentityModel/IdentityModel.OidcClient/blob/master/src/CryptoHelper.cs.
 */

 /* global Windows */

var BinaryStringEncoding = Windows.Security.Cryptography.BinaryStringEncoding;
var CryptographicBuffer = Windows.Security.Cryptography.CryptographicBuffer;
var HashAlgorithmNames = Windows.Security.Cryptography.Core.HashAlgorithmNames;
var HashAlgorithmProvider = Windows.Security.Cryptography.Core.HashAlgorithmProvider;

var OidcConstants = require("./oidcConstants");

var sha256 = HashAlgorithmProvider.openAlgorithm(HashAlgorithmNames.sha256).createHash();

function createState() {
    return createUniqueId(16);
}
exports.createState = createState;

function createNonce() {
    return createUniqueId(16);
}
exports.createNonce = createNonce;

function createPkceData() {
    var codeVerifier = createUniqueId(16);
    var codeChallenge = createCodeChallenge(codeVerifier);
    return {
        codeVerifier: codeVerifier,
        codeChallenge: codeChallenge,
        codeChallengeMethod: OidcConstants.CODE_CHALLENGE_METHOD_S256
    };
}
exports.createPkceData = createPkceData;

var PLUS_SIGN = /\+/g;
var FORWARD_SLASH = /\//g;

function createCodeChallenge(codeVerifier) {
    // Use the S256 method from https://tools.ietf.org/html/rfc7636#section-4.2
    var buffer = CryptographicBuffer.convertStringToBinary(codeVerifier, BinaryStringEncoding.utf8);
    sha256.append(buffer);
    buffer = sha256.getValueAndReset();
    var codeChallenge = CryptographicBuffer.encodeToBase64String(buffer);
    // Need to produce a base64url-encoded string without padding.
    // See https://tools.ietf.org/html/rfc7636#appendix-A
    codeChallenge = codeChallenge.split("=")[0];
    codeChallenge = codeChallenge.replace(PLUS_SIGN, "-");
    codeChallenge = codeChallenge.replace(FORWARD_SLASH, "_");
    return codeChallenge;
}

function createUniqueId(byteLength) {
    var buffer = CryptographicBuffer.generateRandom(byteLength);
    return CryptographicBuffer.encodeToHexString(buffer);
}
exports.createUniqueId = createUniqueId;

