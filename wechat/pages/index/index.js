const { callApi } = require('../../utils/api');

const MODES = [
  { id: 'plain', title: '普通传输', description: '明文请求与响应' },
  { id: 'bidirectional', title: '双向加密', description: '请求和响应均加密' },
  { id: 'request-only', title: '请求加密', description: '仅加密敏感请求' },
  { id: 'response-only', title: '响应加密', description: '仅加密敏感响应' }
];

// plain 与 response-only 复用「明文请求内容」输入形态，其余模式收集敏感字段
const PLAIN_INPUT_MODES = ['plain', 'response-only'];

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
    name: '',
    phone: '',
    email: '',
    address: '',
    plainData: '普通请求示例',
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
      this.setData({ error: error.message || '请求失败' });
    } finally {
      this.setData({ loading: false });
    }
  }
});
