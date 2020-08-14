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
config.options.encrypt = false;
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

const logError = (err, file) => {
    console.log('WRITING:: ', file)
    fs.writeFileSync('./Errorlog' + file, err, function(err) {
        if(err) {
            return console.log(err);
        }
        console.log("The file was saved!");
    } )
}

const dropKeys = (connection, numberOfKeys, done, cb) => {
    if (numberOfKeys > 0) {
        const request = new Request(`
        if exists (SELECT name from sys.column_encryption_keys where name='CEK${numberOfKeys}')
        begin 
        drop column encryption key CEK${numberOfKeys}
        end;
        `, (err) => {
            if (err) {
                logError(err, '55');
                return done(err);
            }
            numberOfKeys -= 1;
            dropKeys(connection, numberOfKeys, done, cb);
        })

        connection.execSql(request);
    } else {
        const request = new Request(`
            if exists (SELECT name from sys.column_master_keys where name='CMK1')
            begin
            drop column master key CMK1
            end;
        `, (err) => {
            if (err) {
                logError(err, '71')
                return done(err)
            }

            return cb();
        });

        connection.execSql(request);
    }
}

describe('always encrypted', function () {
    const numberOfKeys = 10;

    this.timeout(100000);
    let connection;

    before(function () {
        if (config.options.tdsVersion < '7_4') {
            this.skip();
        }
    });

    beforeEach(function (done) {
        connection = new Connection(config);
        connection.on('connect', () => {
            const request = new Request('IF OBJECT_ID(\'dbo.test_always_encrypted\', \'U\') IS NOT NULL DROP TABLE dbo.test_always_encrypted;', (err) => {
                if (err) {
                    logError(err + '98')
                    return done(err)
                }
                dropKeys(connection, numberOfKeys, done, () => {

                    const request = new Request(`if exists (SELECT name from sys.column_master_keys where name='CMK1')
                    begin
                    drop column master key CMK1
                    end;`, (err) => {
                        if (err) {
                            logError(err + '108', '108');
                            connection.close();
                            return done(err);
                        }
                        const request = new Request(`CREATE COLUMN MASTER KEY [CMK1] WITH (
                    KEY_STORE_PROVIDER_NAME = 'TEST_KEYSTORE',
                    KEY_PATH = 'some-arbitrary-keypath'
                  );`, (err) => {
                            if (err) {
                                logError(err + '117', '117')
                                connection.close();
                                return done(err);
                            }
                            return done();
                        })
                        connection.execSql(request);
                    });

                    connection.execSql(request)
                })
            })

            connection.execSql(request);
        })
    });

    afterEach(function (done) {
        if (!connection.closed) {
            const request = new Request('IF OBJECT_ID(\'dbo.test_always_encrypted\', \'U\') IS NOT NULL DROP TABLE dbo.test_always_encrypted;', (err) => {
                if (err) {
                    logError(err + '138', '138')
                    return done(err);
                }
                dropKeys(connection, numberOfKeys, done, () => {

                    connection.on('end', done);
                    connection.close();
                })
            })

            connection.execSql(request);

        } else {
            done();
        }
    });

    it('should correctly insert/select the encrypted data', function (done) {
        function createKeys(numberOfKeys, cb) {
            if (numberOfKeys > 0) {
                const request = new Request(`CREATE COLUMN ENCRYPTION KEY [CEK${numberOfKeys}] WITH VALUES (
                        COLUMN_MASTER_KEY = [CMK1],
                        ALGORITHM = 'RSA_OAEP',
                        ENCRYPTED_VALUE = 0xDEADBEEF
                      );`, (err) => {
                    if (err) {
                        logError(err + '164', '164')
                        return done(err);
                    }
                    numberOfKeys -= 1;
                    createKeys(numberOfKeys, cb);
                });

                connection.execSql(request);
            } else {
                return cb();
            }
        }

        createKeys(numberOfKeys, () => {
            let sqlTableCreate = 'create table test_always_encrypted (';
            for (let i = numberOfKeys; i > 1; i--) {
                sqlTableCreate += "c" + i + " nvarchar(50) COLLATE Latin1_General_BIN2 ENCRYPTED WITH (ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256', COLUMN_ENCRYPTION_KEY = CEK" + i + ") NULL,"
            }

            sqlTableCreate += "c" + 1 + " nvarchar(50) COLLATE Latin1_General_BIN2 ENCRYPTED WITH (ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256', COLUMN_ENCRYPTION_KEY = CEK" + 1 + ") NULL ); "

            const request = new Request(sqlTableCreate, (err) => {
                if (err) {
                    logError(err + '187', '187')
                    return done(err);
                }
                let sql = 'insert into test_always_encrypted values ('

                for(let i = numberOfKeys; i > 1; i--) {
                    sql += `@p${i}, `
                }

                sql += '@p1);'

                const request = new Request(sql, (err) => {
                    if(err) {
                        logError(err + '200', '200')
                        return done(err);
                    }

                    let values = [];
                    //select * from test_always_encrypted
                    const request2 = new Request(`select * from test_always_encrypted`, (err) => {
                        if(err) {
                            logError(err + '207', '207')
                            return done(err);
                        }

                        console.log(values);

                        return done();
                    })

                    request2.on('row', (columns) => {
                        values = columns.map((col) => col.value);
                    })

                    connection.execSql(request2);
                    // return done();
                })

                for(let i = numberOfKeys; i > 0; i--) {
                    request.addParameter(`p${i}`, TYPES.NVarChar, 'nvarchar_determ_test_val123')
                }

                connection.execSql(request);
            });

            connection.execSql(request);
        })

    });
});
