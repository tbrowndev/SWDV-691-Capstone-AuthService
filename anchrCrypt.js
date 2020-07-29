'use strict'
require('argon2');

export class anchrEncrypt {

    constructor() {
    };

    encrypt(p) {
        try {
            const h = argon2.hash(p, {
                type: argon2.argon2i,
                memoryCost: 32,
                hashLength: 30,
            });
            return h;
        } catch (err) {
            throw err; //internal failure
        }
    }

    check(ui, hp) {
        try {
            if (argon2.verify(hp, ui)) {
                return true // password match
            } else {
                return false // password did not match
            }
        } catch (err) {
            return 500 // internal failure
        }
    }
}