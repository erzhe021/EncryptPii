const SERVER_BASE_URL = 'http://localhost:9090'; //spring web server with crypto SDK
// const SERVER_BASE_URL = 'https://local.kong.test:18443'; //kong with lua crypto plugin

module.exports = {
    SERVER_BASE_URL,
    SDK_OPTIONS: {
        baseUrl: SERVER_BASE_URL,
        timeoutMs: 15000,
        publicKeyPath: '/sensitive-transport-crypto/public-key'
    },
    REQUESTS: {
        'plain': {mode: 'plain', endpoint: '/plain/server/normal'},
        'bidirectional': {mode: 'bidirectional', endpoint: '/crypto/server/bidirectional'},
        'request-only': {mode: 'request-only', endpoint: '/crypto/server/request-only'},
        'response-only': {mode: 'response-only', endpoint: '/crypto/server/response-only'},
        'response-only/client-exception': {
            mode: 'response-only', endpoint: '/crypto/server/response-only/client-exception'
        },
        'response-only/system-exception': {
            mode: 'response-only', endpoint: '/crypto/server/response-only/system-exception'
        },
        'response-only/business-exception': {
            mode: 'response-only', endpoint: '/crypto/server/response-only/business-exception'
        }
    }
};
