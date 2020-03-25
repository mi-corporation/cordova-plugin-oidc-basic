/* globals Windows */
function isValidUrl(url) {
    try {
        // Make sure both Windows.Foundation.Uri and JS native URL like the URL, since we'll
        // use both to process URLs depending on who the consumer is.
        new Windows.Foundation.Uri(url);
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}
exports.isValidUrl = isValidUrl;
