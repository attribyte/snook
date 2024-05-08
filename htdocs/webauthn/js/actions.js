function registerUser() {

    username = $("#username").val()
    if (username === "") {
        alert("A username is required");
        return;
    }

    $.get(
        '/register/challenge/' + username,
        null,
        function (data) {
            return data
        },
        'json')
        .then((credentialCreationOptions) => {

            credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
            credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);

            return navigator.credentials.create({
                publicKey: credentialCreationOptions.publicKey
            })
        })
        .then((credential) => {

            let attestationObject = credential.response.attestationObject;
            let clientDataJSON = credential.response.clientDataJSON;
            let rawId = credential.rawId;

            $.post(
                '/register/finish/' + username,
                JSON.stringify({
                    id: credential.id,
                    rawId: bufferEncode(rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferEncode(attestationObject),
                        clientDataJSON: bufferEncode(clientDataJSON),
                    },
                }),
                function (data) {
                    return data
                },
                'json')
        })
        .then((success) => {
            alert("Registered " + username + "!")
            return
        })
        .catch((error) => {
            console.log(error)
            alert("Failed to register " + username)
        })
}

function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");;
}