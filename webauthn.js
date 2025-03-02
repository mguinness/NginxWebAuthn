function atobarray(sBase64) {
    var sBinaryString = atob(sBase64), aBinaryView = new Uint8Array(sBinaryString.length);
    Array.prototype.forEach.call(aBinaryView, function (el, idx, arr) { arr[idx] = sBinaryString.charCodeAt(idx); });
    return aBinaryView;
}

function barraytoa(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

async function configure() {
    try {
        let data = await fetch('/auth/get_challenge_for_new_key', { method: 'POST' });
        let json = await data.json()
        json.publicKey.challenge = atobarray(json.publicKey.challenge)
        json.publicKey.user.id = atobarray(json.publicKey.user.id)
        let cred = await navigator.credentials.create(json)
        window.command.innerHTML = 'On your server, save this key in appsettings under realms section:<br /><pre>"' + window.location.hostname + '": "' + barraytoa(cred.rawId) + ' ' + barraytoa(cred.response.getPublicKey()) + '"</pre>'
    } catch (e) {
        console.log(e)
    }
}

(async function init() {
    try {
        let data = await fetch('/auth/get_challenge_for_existing_key', { method: 'POST' });
        let json = await data.json()
        if (json.publicKey !== undefined) {
            json.publicKey.challenge = atobarray(json.publicKey.challenge)
            json.publicKey.allowCredentials[0].id = atobarray(json.publicKey.allowCredentials[0].id)
            let result = await navigator.credentials.get(json)
            await fetch('/auth/complete_challenge_for_existing_key', { method: 'POST', body: JSON.stringify({
                id: barraytoa(result.rawId),
                authenticatorData: barraytoa(result.response.authenticatorData),
                clientDataJSON: barraytoa(result.response.clientDataJSON),
                signature: barraytoa(result.response.signature)
            }), headers:{ 'Content-Type': 'application/json' }})
            window.location.href = "/"
        }
        if (json.error == 'not_configured') {
            configure();
        }
    } catch(e) {
        console.log(e);
    }
})()