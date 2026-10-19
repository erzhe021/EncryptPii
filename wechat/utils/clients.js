const { SERVICES } = require('../config');
const { createClientFactory } = require('./client-factory');

module.exports = createClientFactory(SERVICES);
