const Connection = require('../../src/connection');
const Request = require('../../src/request');
const TYPES = require('../../src/data-type').typeByName;

const fs = require('fs');
const { assert } = require('chai');

const config = JSON.parse(
    fs.readFileSync(require('os').homedir() + '/.tedious/test-connection.json', 'utf8')
).config;

config.options.debug = {
    packet: true,
    data: true,
    payload: true,
    token: true,
    log: true
};
config.options.columnEncryptionSetting = true;
const alwaysEncryptedCEK = Buffer.from([
    // decrypted column key must be 32 bytes long for AES256
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
config.options.encryptionKeyStoreProviders = [{
    key: 'TEST_KEYSTORE',
    value: {
        decryptColumnEncryptionKey: () => Promise.resolve(alwaysEncryptedCEK),
    },
}];
config.options.tdsVersion = process.env.TEDIOUS_TDS_VERSION;

const createKeys = (connection, numOfKeys, done, cb) => {
    if (numOfKeys > 0) {
        const request = new Request(`CREATE COLUMN ENCRYPTION KEY [CEK${i}] WITH VALUES (
                COLUMN_MASTER_KEY = [CMK1],
                ALGORITHM = 'RSA_OAEP',
                ENCRYPTED_VALUE = 0xDEADBEEF
              );`, (err) => {
            if (err) {
                return done(err);
            }
            numOfKeys -= 1;
            createKeys(connection, numOfKeys, done, cb);
        });
        connection.execSql(request);
    } else {
        return cb();
    }
}

dropKeys = (connection, numberOfKeys, done, cb) => {

}

describe('always encrypted', function () {
    const numberOfKeys = 102;

    this.timeout(100000);
    let connection;

    before(function () {
        if (config.options.tdsVersion < '7_4') {
            this.skip();
        }
    });

    beforeEach(function (done) {
        connection = new Connection(config);
        connection.execSql(new Request(`CREATE COLUMN MASTER KEY [CMK1] WITH (
            KEY_STORE_PROVIDER_NAME = 'TEST_KEYSTORE',
            KEY_PATH = 'some-arbitrary-keypath'
          );`, (err) => {
            if (err) {
                return done(err);
            }
            return done();
        }))
    });

    afterEach(function (done) {
        if (!connection.closed) {

            dropKeys(() => {
                connection.on('end', done);
                connection.close();
            })
        } else {
            done();
        }
    });

    it('should correctly insert/select the encrypted data', function (done) {
        createKeys(connection, numberOfKeys, done, () => {
            let sqlTableCreate = 'create table test_always_encrypted (';
            for (let i = numberOfKeys; i > 1; i--) {
                sqlTableCreate += "c" + i + " varchar(10) COLLATE Latin1_General_BIN2 ENCRYPTED WITH (ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256', COLUMN_ENCRYPTION_KEY = CEK" + i + ") NULL,"
            }

            sqlTableCreate += "c" + 1 + " varchar(10) COLLATE Latin1_General_BIN2 ENCRYPTED WITH (ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256', COLUMN_ENCRYPTION_KEY = CEK" + 1 + ") NULL ); "

            const request = new Request(sqlTableCreate, (err) => {
                if (err) {
                    return done(err);
                }

                return done();
            });

            connection.execSql(request);
        })
    });
});
