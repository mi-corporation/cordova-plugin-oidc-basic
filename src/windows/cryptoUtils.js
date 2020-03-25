/**
 * A partial port of OIDTokenUtilities module from AppAuth-iOS (https://github.com/openid/AppAuth-iOS).
 * See https://github.com/openid/AppAuth-iOS/blob/master/Source/OIDTokenUtilities.m.
 */

 /* global Windows */

var BinaryStringEncoding = Windows.Security.Cryptography.BinaryStringEncoding;
var CryptographicBuffer = Windows.Security.Cryptography.CryptographicBuffer;
var HashAlgorithmNames = Windows.Security.Cryptography.Core.HashAlgorithmNames;
var HashAlgorithmProvider = Windows.Security.Cryptography.Core.HashAlgorithmProvider;

var sha256 = HashAlgorithmProvider.openAlgorithm(HashAlgorithmNames.sha256).createHash();

/**
 * Create a URL safe (and ASCII only) identifier encoding byteLength random bytes
 */
function createRandomId(byteLength) {
    return encodeAsBase64UrlWithoutPadding(CryptographicBuffer.generateRandom(byteLength));
}
exports.createRandomId = createRandomId;

/**
 * Compute an S256 code challenge as specified by https://tools.ietf.org/html/rfc7636#section-4.2.
 * Calling code MUST ensure that the codeVerifier is ASCII only.
 */
function computeS256CodeChallenge(codeVerifier) {
    return encodeAsBase64UrlWithoutPadding(computeSha256(codeVerifier));
}
exports.computeS256CodeChallenge = computeS256CodeChallenge;

/**
 * Get an IBuffer containing the SHA256 of the provided string.
 */
function computeSha256(inputStr) {
    sha256.append(CryptographicBuffer.convertStringToBinary(inputStr, BinaryStringEncoding.utf8));
    return sha256.getValueAndReset();
}
exports.computeSha256 = computeSha256;

var PLUS_SIGN = /\+/g;
var FORWARD_SLASH = /\//g;

/**
 * Encode an IBuffer as a base64 URL without padding as specified by https://tools.ietf.org/html/rfc7636#appendix-A
 */
function encodeAsBase64UrlWithoutPadding(buffer) {
    var base64 = CryptographicBuffer.encodeToBase64String(buffer);
    base64 = base64.split("=")[0];
    base64 = base64.replace(PLUS_SIGN, "-");
    base64 = base64.replace(FORWARD_SLASH, "_");
    return base64;
}
exports.encodeAsBase64UrlWithoutPadding = encodeAsBase64UrlWithoutPadding;
