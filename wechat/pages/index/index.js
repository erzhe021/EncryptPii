const { callApi } = require('../../utils/api');

const MODES = [
  { id: 'plain', title: '普通传输', description: '明文请求与响应' },
  { id: 'bidirectional', title: '双向加密', description: '请求和响应均加密' },
  { id: 'request-only', title: '请求加密', description: '仅加密敏感请求' },
  { id: 'response-only', title: '响应加密(正常)', description: '仅加密敏感响应' },
  { id: 'response-only/business-exception', title: '响应加密(业务异常)', description: 'HTTP 200 业务异常' },
  { id: 'response-only/client-exception', title: '响应加密(客户端异常)', description: 'HTTP 400 客户端异常' },
  { id: 'response-only/system-exception', title: '响应加密(服务端异常)', description: 'HTTP 500 服务端异常' }
];

function isResponseOnly(mode) {
  return mode === 'response-only' || mode.startsWith('response-only/');
}

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
  return mode === 'plain' || isResponseOnly(mode);
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

function formatResult(value) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function isTransmittedField(mode, field) {
  const transmittedFields = {
    plain: ['requestPlain', 'responsePlain'],
    bidirectional: ['requestCipher', 'responseCipher'],
    'request-only': ['requestCipher', 'responsePlain'],
    'response-only': ['requestPlain', 'responseCipher']
  };
  return transmittedFields[isResponseOnly(mode) ? 'response-only' : mode].includes(field);
}

function resultLabel(title, mode, field, value, direction) {
  return isTransmittedField(mode, field) && value !== 'N/A'
    ? `${title}（${direction}）`
    : title;
}

Page({
  data: {
    modes: MODES,
    mode: 'bidirectional',
    usesPlainInput: false,
    name: '张三',
    phone: '11111111111',
    email: 'zhangsan@example.com',
    address: '上海市长宁区某某广场办公A楼',
    plainData: 'hello world',
    loading: false,
    error: '',
    result: null
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

    this.setData({ loading: true, error: '', result: null });
    try {
      let result;
      try {
        result = await callApi(mode, payload);
      } catch (error) {
        if (!error.result) {
          throw error;
        }
        result = error.result;
        this.setData({ error: errorMessage(error) });
      }
      const values = {
        requestPlain: formatResult(isResponseOnly(mode)
          ? { headers: result.stcHeaders, body: result.requestPlain }
          : result.requestPlain),
        requestCipher: result.requestCipher ? formatResult(result.requestCipher) : 'N/A',
        responsePlain: result.responsePlain === null ? 'N/A' : formatResult(result.responsePlain),
        responseCipher: result.responseCipher ? formatResult(result.responseCipher) : 'N/A',
        latency: formatResult(result.latency)
      };
      this.setData({
        result: {
          ...values,
          requestPlainLabel: resultLabel('请求明文', mode, 'requestPlain', values.requestPlain, '实发'),
          requestCipherLabel: resultLabel('请求密文', mode, 'requestCipher', values.requestCipher, '实发'),
          responsePlainLabel: resultLabel('响应明文', mode, 'responsePlain', values.responsePlain, '实收'),
          responseCipherLabel: resultLabel('响应密文', mode, 'responseCipher', values.responseCipher, '实收')
        }
      });
    } catch (error) {
      this.setData({ error: errorMessage(error) });
    } finally {
      this.setData({ loading: false });
    }
  }
});

function errorMessage(error) {
  return error.code === 'HTTP_ERROR'
    ? `请求失败（HTTP ${error.statusCode}）`
    : ERROR_MESSAGES[error.code] || '请求失败';
}
