const { callApi } = require('../../utils/api');

const MODES = [
  { id: 'plain', title: '普通传输', description: '明文请求与响应' },
  { id: 'bidirectional', title: '双向加密', description: '请求和响应均加密' },
  { id: 'request-only', title: '请求加密', description: '仅加密敏感请求' },
  { id: 'response-only', title: '响应加密', description: '仅加密敏感响应' }
];

// plain 与 response-only 复用「明文请求内容」输入形态，其余模式收集敏感字段
const PLAIN_INPUT_MODES = ['plain', 'response-only'];

const ERROR_MESSAGES = {
  INVALID_ARGUMENT: '请检查服务地址和请求参数。',
  NETWORK_ERROR: '网络请求失败，请检查网络连接。',
  RANDOM_UNAVAILABLE: '无法获取安全随机数，请确认微信版本支持该功能。',
  INVALID_SERVER_KEY: 'Kong 返回的公钥信息无效或已过期。',
  ENCRYPTION_FAILED: '请求加密失败。',
  INVALID_CIPHER_PAYLOAD: '加密响应格式无效。',
  DECRYPTION_FAILED: '响应认证或解密失败。',
  INVALID_RESPONSE: '服务响应格式无效。',
  KEY_RETRY_FAILED: '公钥刷新后重试失败。'
};

function usesPlainInput(mode) {
  return PLAIN_INPUT_MODES.includes(mode);
}

function buildPayload(mode, data) {
  if (usesPlainInput(mode)) {
    return { data: data.plainData };
  }
  return {
    name: data.name.trim(),
    phone: data.phone.trim(),
    email: data.email.trim(),
    address: data.address.trim()
  };
}

Page({
  data: {
    modes: MODES,
    mode: 'bidirectional',
    usesPlainInput: false,
    name: 'eric',
    phone: '13764641531',
    email: 'eric.zheng@ingka.ikea.com',
    address: '上海市长宁区荟聚中心办公A楼',
    plainData: 'hello world',
    loading: false,
    error: '',
    result: ''
  },

  selectMode(event) {
    const mode = event.currentTarget.dataset.mode;
    this.setData({
      mode,
      usesPlainInput: usesPlainInput(mode),
      error: '',
      result: ''
    });
  },

  onSensitiveInput(event) {
    const field = event.currentTarget.dataset.field;
    this.setData({ [field]: event.detail.value });
  },

  onPlainInput(event) {
    this.setData({ plainData: event.detail.value });
  },

  async submit() {
    if (this.data.loading) {
      return;
    }

    const mode = this.data.mode;
    const payload = buildPayload(mode, this.data);

    if (!usesPlainInput(mode) && Object.values(payload).some((value) => !value)) {
      this.setData({ error: '请填写完整的敏感数据。' });
      return;
    }

    this.setData({ loading: true, error: '', result: '' });
    try {
      const result = await callApi(mode, payload);
      this.setData({ result: JSON.stringify(result, null, 2) });
    } catch (error) {
      const message = error.code === 'HTTP_ERROR'
        ? `请求失败（HTTP ${error.statusCode}）`
        : ERROR_MESSAGES[error.code] || '请求失败';
      this.setData({ error: message });
    } finally {
      this.setData({ loading: false });
    }
  }
});
