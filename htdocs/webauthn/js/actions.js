function registerUser() {

    username = $("#email").val()
    if (username === "") {
        alert("A username is required!");
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
            // TODO
        })
}

function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}