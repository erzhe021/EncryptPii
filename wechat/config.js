module.exports = {
    SERVICES: {
        demo: {
            baseUrl: 'http://localhost:9090',
            crypto: { enabled: true },
            timeoutMs: 15000,
            publicKeyPath: '/sensitive-transport-crypto/public-key'
        }
    },
    REQUESTS: {
        'plain': {service: 'demo', mode: 'plain', endpoint: '/plain/server/normal'},
        'bidirectional': {service: 'demo', mode: 'bidirectional', endpoint: '/crypto/server/bidirectional'},
        'request-only': {service: 'demo', mode: 'request-only', endpoint: '/crypto/server/request-only'},
        'response-only': {service: 'demo', mode: 'response-only', endpoint: '/crypto/server/response-only'},
        'response-only/client-exception': {
            service: 'demo',
            mode: 'response-only', endpoint: '/crypto/server/response-only/client-exception'
        },
        'response-only/system-exception': {
            service: 'demo',
            mode: 'response-only', endpoint: '/crypto/server/response-only/system-exception'
        },
        'response-only/business-exception': {
            service: 'demo',
            mode: 'response-only', endpoint: '/crypto/server/response-only/business-exception'
        }
    }
};
