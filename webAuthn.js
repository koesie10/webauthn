class WebAuthn {
	// Decode a base64 string into a Uint8Array.
	static _decodeBuffer(value) {
		return Uint8Array.from(atob(value), c => c.charCodeAt(0));
	}

	// Encode an ArrayBuffer into a base64 string.
	static _encodeBuffer(value) {
		return btoa(new Uint8Array(value).reduce((s, byte) => s + String.fromCharCode(byte), ''));
	}

	// Checks whether the status returned matches the status given.
	static _checkStatus(status) {
		return res => {
			if (res.status === status) {
				return res;
			}
			throw new Error(res.statusText);
		};
	}

	register() {
		return fetch('/webauthn/registration/start', {
				method: 'POST'
			})
			.then(WebAuthn._checkStatus(200))
			.then(res => res.json())
			.then(res => {
				res.publicKey.challenge = WebAuthn._decodeBuffer(res.publicKey.challenge);
				res.publicKey.user.id = WebAuthn._decodeBuffer(res.publicKey.user.id);
				if (res.publicKey.excludeCredentials) {
					for (var i = 0; i < res.publicKey.excludeCredentials.length; i++) {
						res.publicKey.excludeCredentials[i].id = WebAuthn._decodeBuffer(res.publicKey.excludeCredentials[i].id);
					}
				}
				return res;
			})
			.then(res => navigator.credentials.create(res))
			.then(credential => {
				return fetch('/webauthn/registration/finish', {
					method: 'POST',
					headers: {
						'Accept': 'application/json',
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						id: credential.id,
						rawId: WebAuthn._encodeBuffer(credential.rawId),
						response: {
							attestationObject: WebAuthn._encodeBuffer(credential.response.attestationObject),
							clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON)
						},
						type: credential.type
					}),
				})
			})
			.then(WebAuthn._checkStatus(201));
	}

	login() {
		return fetch('/webauthn/login/start', {
				method: 'POST'
			})
			.then(WebAuthn._checkStatus(200))
			.then(res => res.json())
			.then(res => {
				res.publicKey.challenge = WebAuthn._decodeBuffer(res.publicKey.challenge);
				if (res.publicKey.allowCredentials) {
					for (let i = 0; i < res.publicKey.allowCredentials.length; i++) {
						res.publicKey.allowCredentials[i].id = WebAuthn._decodeBuffer(res.publicKey.allowCredentials[i].id);
					}
				}
				return res;
			})
			.then(res => navigator.credentials.get(res))
			.then(credential => {
				return fetch('/webauthn/login/finish', {
					method: 'POST',
					headers: {
						'Accept': 'application/json',
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						id: credential.id,
						rawId: WebAuthn._encodeBuffer(credential.rawId),
						response: {
							clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON),
							authenticatorData: WebAuthn._encodeBuffer(credential.response.authenticatorData),
							signature: WebAuthn._encodeBuffer(credential.response.signature),
							userHandle: WebAuthn._encodeBuffer(credential.response.userHandle),
						},
						type: credential.type
					}),
				})
			})
			.then(WebAuthn._checkStatus(200));
	}
}