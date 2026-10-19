const { createWechatClient, SdkError } = require('../sdk/index');

function createClientFactory(services, create = createWechatClient) {
  if (!services || typeof services !== 'object' || Array.isArray(services)
      || typeof create !== 'function') {
    throw new SdkError('INVALID_ARGUMENT', 'A service registry and client constructor are required');
  }
  const registry = new Map();
  for (const [name, options] of Object.entries(services)) {
    if (!name || !options || typeof options !== 'object' || Array.isArray(options)) {
      throw new SdkError('INVALID_ARGUMENT', 'Invalid service configuration');
    }
    registry.set(name, {
      ...options,
      ...(options.crypto && typeof options.crypto === 'object' && !Array.isArray(options.crypto)
        ? { crypto: { ...options.crypto } } : {}),
      ...(options.headers && typeof options.headers === 'object' && !Array.isArray(options.headers)
        ? { headers: { ...options.headers } } : {})
    });
  }
  const clients = new Map();

  function requireService(service) {
    if (typeof service !== 'string' || !registry.has(service)) {
      throw new SdkError('INVALID_ARGUMENT', 'Unknown application service');
    }
  }

  return {
    getClient(service) {
      requireService(service);
      if (!clients.has(service)) {
        clients.set(service, create(registry.get(service)));
      }
      return clients.get(service);
    },
    clear(service) {
      requireService(service);
      clients.delete(service);
    },
    clearAll() {
      clients.clear();
    }
  };
}

module.exports = { createClientFactory };
