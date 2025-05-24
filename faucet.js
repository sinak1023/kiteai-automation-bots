const axios = require('axios');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const crypto = require('crypto');
const Web3 = require('web3');
const chalk = require('chalk');
const moment = require('moment-timezone');
const UserAgents = require('user-agents');
const fs = require('fs').promises;
const readline = require('readline');
require('dotenv').config();

const wib = 'Asia/Jakarta';

class KiteFaucetStake {
  constructor() {
    console.log(chalk.blue.bold('Initializing KiteFaucetStake class...'));
    this.headers = {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
      'Origin': 'https://testnet.gokite.ai',
      'Referer': 'https://testnet.gokite.ai/',
      'Sec-Fetch-Dest': 'empty',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Site': 'same-site'
    };
    this.NEO_API = 'https://neo.prod.gokite.ai/v2';
    this.OZONE_API = 'https://ozone-point-system.prod.gokite.ai';
    this.KEY_HEX = '6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a';
    this.proxies = [];
    this.proxyIndex = 0;
    this.accountProxies = {};
    this.authTokens = {};
    this.accessTokens = {};
    this.headerCookies = {};
    try {
      console.log(chalk.blue.bold('Attempting to initialize Web3...'));
      this.web3 = new Web3();
      console.log(chalk.green.bold('Web3 initialized successfully'));
    } catch (e) {
      console.log(chalk.red.bold(`Failed to initialize Web3: ${e.message}`));
      throw e;
    }
  }

  getUserAgent() {
    return new UserAgents().toString();
  }

  clearTerminal() {
    console.clear();
  }

  log(message) {
    console.log(
      `${chalk.cyan.bold(`[ ${moment().tz(wib).format('MM/DD/YY HH:mm:ss z')} ]`)}` +
      `${chalk.white.bold(' | ')}${message}`
    );
  }

  welcome() {
    console.log(
      chalk.green.bold(`
 ██ ▄█▀▄▄▄       ▄████▄   ██░ ██  ▄▄▄       ██▓        ▄▄▄▄    ▒█████  ▄▄▄█████▓  ██████ 
 ██▄█▒▒████▄    ▒██▀ ▀█  ▓██░ ██▒▒████▄    ▓██▒       ▓█████▄ ▒██▒  ██▒▓  ██▒ ▓▒▒██    ▒ 
▓███▄░▒██  ▀█▄  ▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄  ▒██░       ▒██▒ ▄██▒██░  ██▒▒ ▓██░ ▒░░ ▓██▄   
▓██ █▄░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██ ▒██░       ▒██░█▀  ▒██   ██░░ ▓██▓ ░   ▒   ██▒
▒██▒ █▄▓█   ▓██▒▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒░██████▒   ░▓█  ▀█▓░ ████▓▒░  ▒██▒ ░ ▒██████▒▒
▒ ▒▒ ▓▒▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒░▓  ░   ░▒▓███▀▒░ ▒░▒░▒░   ▒ ░░   ▒ ▒▓▒ ▒ ░
░ ░▒ ▒░ ▒   ▒▒ ░  ░  ▒    ▒ ░▒░ ░  ▒   ▒▒ ░░ ░ ▒  ░   ▒░▒   ░   ░ ▒ ▒░     ░    ░ ░▒  ░ ░
░ ░░ ░  ░   ▒   ░         ░  ░░ ░  ░   ▒     ░ ░       ░    ░ ░ ░ ░ ▒    ░      ░  ░  ░  
░  ░        ░  ░░ ░       ░  ░  ░      ░  ░    ░  ░    ░          ░ ░                 ░  
                ░                                           ░                            
      `)
    );
    console.log(
      `${chalk.green.bold('Auto Faucet & Stake BOT by ostadkachal\n')}`
    );
  }

  async loadProxies(useProxyChoice) {
    const filename = 'proxy.txt';
    this.log(`${chalk.blue.bold(`Attempting to load proxies with choice: ${useProxyChoice}`)}`);
    try {
      if (useProxyChoice === 1) {
        this.log(`${chalk.blue.bold('Fetching proxies from Monosans URL...')}`);
        const response = await axios.get('https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt', { timeout: 30000 });
        await fs.writeFile(filename, response.data);
        this.proxies = response.data.split('\n').filter(line => line.trim());
      } else {
        if (!await fs.access(filename).then(() => true).catch(() => false)) {
          this.log(`${chalk.red.bold(`File ${filename} Not Found.`)}`);
          return;
        }
        const content = await fs.readFile(filename, 'utf-8');
        this.proxies = content.split('\n').filter(line => line.trim());
      }

      if (!this.proxies.length) {
        this.log(`${chalk.red.bold('No Proxies Found.')}`);
        return;
      }

      this.log(
        `${chalk.green.bold('Proxies Total  : ')}` +
        `${chalk.white.bold(this.proxies.length)}`
      );
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed To Load Proxies: ${e.message}`)}`);
      this.proxies = [];
    }
  }

  checkProxySchemes(proxies) {
    const schemes = ['http://', 'https://', 'socks4://', 'socks5://'];
    if (schemes.some(scheme => proxies.startsWith(scheme))) return proxies;
    return `http://${proxies}`;
  }

  getNextProxyForAccount(token) {
    if (!this.accountProxies[token]) {
      if (!this.proxies.length) return null;
      const proxy = this.checkProxySchemes(this.proxies[this.proxyIndex]);
      this.accountProxies[token] = proxy;
      this.proxyIndex = (this.proxyIndex + 1) % this.proxies.length;
    }
    return this.accountProxies[token];
  }

  rotateProxyForAccount(token) {
    if (!this.proxies.length) return null;
    const proxy = this.checkProxySchemes(this.proxies[this.proxyIndex]);
    this.accountProxies[token] = proxy;
    this.proxyIndex = (this.proxyIndex + 1) % this.proxies.length;
    return proxy;
  }

  generateAddress(privateKey) {
    this.log(`${chalk.blue.bold(`Generating address for private key: ${privateKey.slice(0, 6)}...${privateKey.slice(-6)}`)}`);
    try {
      if (!/^[0-9a-fA-F]{64}$/.test(privateKey)) {
        throw new Error('Invalid private key format: must be 64 hexadecimal characters');
      }
      const formattedKey = privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`;
      const account = this.web3.eth.accounts.privateKeyToAccount(formattedKey);
      this.log(`${chalk.green.bold(`Generated address: ${account.address}`)}`);
      return account.address;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to generate address: ${e.message}`)}`);
      return null;
    }
  }

  hexToBytes(hexStr) {
    try {
      return Buffer.from(hexStr, 'hex');
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to convert hex to bytes: ${e.message}`)}`);
      return null;
    }
  }

  bytesToHex(bytes) {
    try {
      return bytes.toString('hex');
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to convert bytes to hex: ${e.message}`)}`);
      return null;
    }
  }

  encrypt(address) {
    this.log(`${chalk.blue.bold(`Encrypting address: ${address}`)}`);
    try {
      const key = this.hexToBytes(this.KEY_HEX);
      if (!key || key.length !== 32) {
        throw new Error('Invalid encryption key');
      }
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      let encrypted = cipher.update(address, 'utf8');
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const authTag = cipher.getAuthTag();
      const result = Buffer.concat([iv, encrypted, authTag]);
      const hexResult = this.bytesToHex(result);
      this.log(`${chalk.green.bold(`Encrypted address successfully`)}`);
      return hexResult;
    } catch (e) {
      this.log(`${chalk.red.bold(`Encryption failed: ${e.message}`)}`);
      return null;
    }
  }

  generateAuthToken(address) {
    this.log(`${chalk.blue.bold(`Generating auth token for address: ${address}`)}`);
    const token = this.encrypt(address);
    if (token) {
      this.log(`${chalk.green.bold(`Auth token generated successfully`)}`);
    }
    return token;
  }

  maskAccount(account) {
    return account.slice(0, 6) + '*'.repeat(6) + account.slice(-6);
  }

  async solveRecaptcha(proxy, captchaService) {
    this.log(`${chalk.blue.bold(`Solving Google reCAPTCHA v2 with ${captchaService}...`)}`);
    try {
      if (captchaService === 'CapSolver') {
        const captchaConfig = {
          clientKey: process.env.CAPSOLVER_API_KEY,
          task: {
            type: proxy ? 'ReCaptchaV2Task' : 'ReCaptchaV2TaskProxyLess',
            websiteURL: 'https://testnet.gokite.ai/',
            websiteKey: '6Lc_VwgrAAAAALtx_UtYQnW-cFg8EPDgJ8QVqkaz'
          }
        };
        if (proxy) {
          this.log(`${chalk.blue.bold(`Using proxy for CAPTCHA: ${proxy}`)}`);
          const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy.replace(/^https?:\/\//, '') : proxy;
          captchaConfig.task.proxy = proxyUrl;
          captchaConfig.task.proxyType = proxyUrl.includes('socks') ? 'SOCKS5' : 'HTTP';
        }
        this.log(`${chalk.blue.bold(`CAPTCHA config: ${JSON.stringify(captchaConfig)}`)}`);

        const createResponse = await axios.post('https://api.capsolver.com/createTask', captchaConfig);
        if (createResponse.data.errorId !== 0) {
          this.log(`${chalk.red.bold(`Failed to create CAPTCHA task: ${createResponse.data.errorDescription}`)}`);
          return null;
        }
        const taskId = createResponse.data.taskId;
        this.log(`${chalk.blue.bold(`CAPTCHA task created: ${taskId}`)}`);

        let attempts = 0;
        const maxAttempts = 30;
        while (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 1000));
          const resultResponse = await axios.post('https://api.capsolver.com/getTaskResult', {
            clientKey: process.env.CAPSOLVER_API_KEY,
            taskId
          });
          if (resultResponse.data.errorId !== 0) {
            this.log(`${chalk.red.bold(`Failed to get CAPTCHA result: ${resultResponse.data.errorDescription}`)}`);
            return null;
          }
          if (resultResponse.data.status === 'ready') {
            const token = resultResponse.data.solution.gRecaptchaResponse;
            this.log(`${chalk.green.bold(`reCAPTCHA solved successfully: ${token.slice(0, 20)}...`)}`);
            return token;
          }
          attempts++;
        }
        this.log(`${chalk.red.bold('CAPTCHA solving timed out')}`);
        return null;
      } else if (captchaService === '2Captcha') {
        const captchaConfig = {
          key: process.env.TWOCAPTCHA_API_KEY,
          method: 'userrecaptcha',
          googlekey: '6Lc_VwgrAAAAALtx_UtYQnW-cFg8EPDgJ8QVqkaz',
          pageurl: 'https://testnet.gokite.ai/',
          json: 1,
          invisible: 0
        };
        if (proxy) {
          this.log(`${chalk.blue.bold(`Using proxy for CAPTCHA: ${proxy}`)}`);
          const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy.replace(/^https?:\/\//, '') : proxy;
          captchaConfig.proxy = proxyUrl;
          captchaConfig.proxytype = proxyUrl.includes('socks') ? 'SOCKS5' : 'HTTP';
        }
        this.log(`${chalk.blue.bold(`CAPTCHA config: ${JSON.stringify(captchaConfig)}`)}`);

        const createResponse = await axios.post('https://2captcha.com/in.php', captchaConfig);
        if (createResponse.data.status !== 1) {
          this.log(`${chalk.red.bold(`Failed to create CAPTCHA task: ${createResponse.data.request}`)}`);
          return null;
        }
        const captchaId = createResponse.data.request;
        this.log(`${chalk.blue.bold(`CAPTCHA task created: ${captchaId}`)}`);

        let attempts = 0;
        const maxAttempts = 30;
        while (attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          const resultResponse = await axios.get(`https://2captcha.com/res.php?key=${process.env.TWOCAPTCHA_API_KEY}&action=get&id=${captchaId}&json=1`);
          if (resultResponse.data.status === 0) {
            if (resultResponse.data.request === 'CAPCHA_NOT_READY') {
              attempts++;
              this.log(`${chalk.blue.bold(`Attempt ${attempts}: CAPTCHA not ready yet...`)}`);
              continue;
            }
            this.log(`${chalk.red.bold(`Failed to get CAPTCHA result: ${resultResponse.data.request}`)}`);
            return null;
          }
          if (resultResponse.data.status === 1) {
            const token = resultResponse.data.request;
            this.log(`${chalk.green.bold(`reCAPTCHA solved successfully: ${token.slice(0, 20)}...`)}`);
            return token;
          }
          attempts++;
        }
        this.log(`${chalk.red.bold('CAPTCHA solving timed out')}`);
        return null;
      }
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to solve reCAPTCHA with ${captchaService}: ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`${captchaService} response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return null;
    }
  }

  async requestFaucet(address, proxy, captchaService) {
    const url = `${this.OZONE_API}/blockchain/faucet-transfer`;
    const data = {};
    const captchaToken = await this.solveRecaptcha(proxy, captchaService);
    if (!captchaToken) {
      this.log(`${chalk.red.bold('Skipping faucet request due to CAPTCHA failure')}`);
      return false;
    }
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'Content-Type': 'application/json',
      'X-Recaptcha-Token': captchaToken,
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for faucet: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.includes('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.post(url, data, config);
      if (response.data?.data === 'ok') {
        this.log(`${chalk.green.bold(`Faucet requested successfully for address: ${this.maskAccount(address)}`)}`);
        return true;
      }
      this.log(`${chalk.red.bold(`Faucet request failed: ${JSON.stringify(response.data)}`)}`);
      return false;
    } catch (e) {
      this.log(`${chalk.red.bold(`Faucet request failed: ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return false;
    }
  }

  async checkBalance(address, proxy) {
    const url = `${this.OZONE_API}/me/balance`;
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for balance check: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.includes('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.get(url, config);
      const balance = response.data?.data?.balances?.kite || 0;
      this.log(`${chalk.green.bold(`Balance for ${this.maskAccount(address)}: ${balance} KITE`)}`);
      return balance;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to check balance: ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return 0;
    }
  }

  async getSubnets(proxy) {
    const url = `${this.OZONE_API}/subnets?page=1&size=100`;
    const headers = {
      ...this.headers,
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for subnets: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.includes('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.get(url, config);
      const subnets = response.data?.data?.slice(0, 3) || [];
      this.log(`${chalk.green.bold(`Fetched ${subnets.length} subnets for staking`)}`);
      return subnets;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to fetch subnets: ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return [];
    }
  }

  async getStakedInfo(address, subnetId, proxy) {
    const url = `${this.OZONE_API}/subnet/${subnetId}/staked-info?id=${subnetId}`;
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for staked info: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.includes('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.get(url, config);
      const stakedInfo = response.data?.data || {};
      this.log(`${chalk.green.bold(`Fetched staked info for subnet ${subnetId}`)}`);
      return stakedInfo;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to fetch staked info for subnet ${subnetId}: ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return null;
    }
  }

  async stake(address, subnetAddress, amount, proxy) {
    const stakeDelay = Math.floor(Math.random() * 2000) + 3000;
    this.log(`${chalk.blue.bold(`Waiting ${stakeDelay / 1000} seconds before staking...`)}`);
    await new Promise(resolve => setTimeout(resolve, stakeDelay));

    const url = `${this.OZONE_API}/subnet/delegate`;
    const data = {
      subnet_address: subnetAddress,
      amount: amount
    };
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'Content-Type': 'application/json',
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for staking: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.includes('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.post(url, data, config);
      const txHash = response.data?.data?.tx_hash || '';
      if (txHash) {
        this.log(`${chalk.green.bold(`tx_hash: ${txHash}`)}`);
      } else {
        this.log(`${chalk.red.bold(`No tx_hash received for staking`)}`);
      }
      return txHash;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to stake: ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return '';
    }
  }

  async userSignin(address, proxy, retries = 5) {
    const url = `${this.NEO_API}/signin`;
    const data = { eoa: address };
    const headers = {
      ...this.headers,
      'Authorization': this.authTokens[address],
      'Content-Length': Buffer.byteLength(JSON.stringify(data)),
      'Content-Type': 'application/json',
      'User-Agent': this.getUserAgent()
    };
    this.log(`${chalk.blue.bold(`Attempting signin for address: ${this.maskAccount(address)}`)}`);
    await new Promise(resolve => setTimeout(resolve, 3000));
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const config = { headers, timeout: 60000 };
        if (proxy) {
          this.log(`${chalk.blue.bold(`Using proxy: ${proxy}`)}`);
          const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
          if (proxyUrl.includes('socks')) {
            config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
          } else {
            config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
          }
        }
        const response = await axios.post(url, data, config);
        const rawCookies = response.headers['set-cookie'] || [];
        if (rawCookies.length) {
          const cookieHeader = this.extractCookies(rawCookies);
          if (cookieHeader) {
            this.log(`${chalk.green.bold(`Signin successful for address: ${this.maskAccount(address)}`)}`);
            return [response.data.data.access_token, cookieHeader];
          }
        }
        this.log(`${chalk.yellow.bold(`No cookies received on attempt ${attempt + 1}`)}`);
      } catch (e) {
        this.log(`${chalk.red.bold(`Signin attempt ${attempt + 1} failed: ${e.message}`)}`);
        if (e.response) {
          this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
        }
        if (attempt < retries - 1) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          continue;
        }
        return [null, null];
      }
    }
    this.log(`${chalk.red.bold(`Signin failed after ${retries} attempts for address: ${this.maskAccount(address)}`)}`);
    return [null, null];
  }

  extractCookies(rawCookies) {
    const cookiesDict = {};
    const skipKeys = ['expires', 'path', 'domain', 'samesite', 'secure', 'httponly', 'max-age'];
    try {
      for (const cookieStr of rawCookies) {
        const cookieParts = cookieStr.split(';');
        for (const part of cookieParts) {
          const cookie = part.trim();
          if (cookie.includes('=')) {
            const [name, value] = cookie.split('=', 2);
            if (name && value && !skipKeys.includes(name.toLowerCase())) {
              cookiesDict[name] = value;
            }
          }
        }
      }
      const cookieHeader = Object.entries(cookiesDict).map(([key, value]) => `${key}=${value}`).join('; ');
      this.log(`${chalk.green.bold(`Extracted cookies: ${cookieHeader}`)}`);
      return cookieHeader;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to extract cookies: ${e.message}`)}`);
      return null;
    }
  }

  async processUserSignin(address, useProxy, rotate) {
    this.log(
      `${chalk.yellow.bold(`Trying to login for address: ${this.maskAccount(address)}`)}`
    );

    let proxy = useProxy ? this.getNextProxyForAccount(address) : null;

    if (rotate) {
      let accessToken, headerCookie;
      while (!accessToken || !headerCookie) {
        [accessToken, headerCookie] = await this.userSignin(address, proxy);
        if (!accessToken || !headerCookie) {
          this.log(
            `${chalk.cyan.bold('Status    :')}` +
            `${chalk.red.bold(' Login Failed ')}` +
            `${chalk.magenta.bold('-')}` +
            `${chalk.yellow.bold(' Rotating Proxy ')}`
          );
          proxy = useProxy ? this.rotateProxyForAccount(address) : null;
          await new Promise(resolve => setTimeout(resolve, 5000));
          continue;
        }
        this.accessTokens[address] = accessToken;
        this.headerCookies[address] = headerCookie;
        this.log(
          `${chalk.cyan.bold('Status    :')}` +
          `${chalk.green.bold(' Login Success ')}`
        );
        return true;
      }
    }

    const [accessToken, headerCookie] = await this.userSignin(address, proxy);
    if (!accessToken || !headerCookie) {
      this.log(
        `${chalk.cyan.bold('Status    :')}` +
        `${chalk.red.bold(' Login Failed ')}` +
        `${chalk.magenta.bold('-')}` +
        `${chalk.yellow.bold(' Skipping This Account ')}`
      );
      return false;
    }

    this.accessTokens[address] = accessToken;
    this.headerCookies[address] = headerCookie;
    this.log(
      `${chalk.cyan.bold('Status    :')}` +
      `${chalk.green.bold(' Login Success ')}`
    );
    return true;
  }

  async processAccount(address, useProxy, rotate, captchaService) {
    this.log(`${chalk.blue.bold(`Processing account: ${this.maskAccount(address)}`)}`);
    const signed = await this.processUserSignin(address, useProxy, rotate);
    if (signed) {
      const proxy = useProxy ? this.getNextProxyForAccount(address) : null;
      this.log(
        `${chalk.cyan.bold('Proxy     :')}` +
        `${chalk.white.bold(` ${proxy || 'None'} `)}`
      );

      // Step 1: Request faucet
      const faucetSuccess = await this.requestFaucet(address, proxy, captchaService);
      if (!faucetSuccess) {
        this.log(`${chalk.red.bold('Skipping account due to faucet failure')}`);
        return;
      }

      // Random delay of 15-20 seconds after faucet
      const faucetDelay = Math.floor(Math.random() * 5000) + 15000;
      this.log(`${chalk.blue.bold(`Waiting ${faucetDelay / 1000} seconds before proceeding...`)}`);
      await new Promise(resolve => setTimeout(resolve, faucetDelay));

      // Step 2: Check balance
      const balance = await this.checkBalance(address, proxy);
      if (balance < 1) {
        this.log(`${chalk.red.bold('Insufficient balance for staking')}`);
        return;
      }

      // Step 3: Get subnets
      const subnets = await this.getSubnets(proxy);
      if (!subnets.length) {
        this.log(`${chalk.red.bold('No subnets available for staking')}`);
        return;
      }

      // Step 4: Select a random subnet from the first 3
      const selectedSubnet = subnets[Math.floor(Math.random() * subnets.length)];
      const subnetId = selectedSubnet.id;
      const subnetAddress = selectedSubnet.address;

      // Step 5: Get staked info
      const stakedInfo = await this.getStakedInfo(address, subnetId, proxy);
      if (!stakedInfo) {
        this.log(`${chalk.red.bold('Skipping staking due to staked info failure')}`);
        return;
      }

      // Step 6: Stake 1 KITE
      const txHash = await this.stake(address, subnetAddress, 1, proxy);
      if (!txHash) {
        this.log(`${chalk.red.bold('Staking failed for account')}`);
      }
    }
  }

  async printQuestion() {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const question = (query) => new Promise(resolve => rl.question(query, resolve));

    this.log(`${chalk.blue.bold('Starting user input collection...')}`);

    // Select CAPTCHA service
    let captchaService;
    while (true) {
      console.log(`${chalk.white.bold('1. Use CapSolver for CAPTCHA')}`);
      console.log(`${chalk.white.bold('2. Use 2Captcha for CAPTCHA')}`);
      const choice = parseInt(await question(`${chalk.blue.bold('Choose CAPTCHA service [1/2] -> ')}`));
      if (choice === 1) {
        captchaService = 'CapSolver';
        if (!process.env.CAPSOLVER_API_KEY) {
          this.log(`${chalk.red.bold('CAPSOLVER_API_KEY is missing in .env file')}`);
          continue;
        }
        this.log(`${chalk.green.bold('CapSolver selected.')}`);
        break;
      } else if (choice === 2) {
        captchaService = '2Captcha';
        if (!process.env.TWOCAPTCHA_API_KEY) {
          this.log(`${chalk.red.bold('TWOCAPTCHA_API_KEY is missing in .env file')}`);
          continue;
        }
        this.log(`${chalk.green.bold('2Captcha selected.')}`);
        break;
      } else {
        this.log(`${chalk.red.bold('Please enter either 1 or 2.')}`);
      }
    }

    // Select proxy option
    let useProxyChoice;
    while (true) {
      console.log(`${chalk.white.bold('1. Run With Monosans Proxy')}`);
      console.log(`${chalk.white.bold('2. Run With Private Proxy')}`);
      console.log(`${chalk.white.bold('3. Run Without Proxy')}`);
      useProxyChoice = parseInt(await question(`${chalk.blue.bold('Choose proxy option [1/2/3] -> ')}`));
      if ([1, 2, 3].includes(useProxyChoice)) {
        const proxyType = useProxyChoice === 1 ? 'Run With Monosans Proxy' : useProxyChoice === 2 ? 'Run With Private Proxy' : 'Run Without Proxy';
        this.log(`${chalk.green.bold(`${proxyType} Selected.`)}`);
        break;
      } else {
        this.log(`${chalk.red.bold('Please enter either 1, 2, or 3.')}`);
      }
    }

    let rotate = false;
    if ([1, 2].includes(useProxyChoice)) {
      while (true) {
        const input = await question(`${chalk.blue.bold('Rotate Invalid Proxy? [y/n] -> ')}`);
        if (['y', 'n'].includes(input.toLowerCase())) {
          rotate = input.toLowerCase() === 'y';
          break;
        } else {
          this.log(`${chalk.red.bold("Invalid input. Enter 'y' or 'n'.")}`);
        }
      }
    }

    rl.close();
    this.log(`${chalk.green.bold(`User input collected: captchaService=${captchaService}, useProxyChoice=${useProxyChoice}, rotate=${rotate}`)}`);
    return { captchaService, useProxyChoice, rotate };
  }

  async main() {
    this.welcome();
    this.log(`${chalk.blue.bold('Starting main function...')}`);
    try {
      this.log(`${chalk.blue.bold('Checking for accounts.txt...')}`);
      if (!await fs.access('accounts.txt').then(() => true).catch(() => false)) {
        throw new Error('accounts.txt not found in the current directory');
      }

      this.log(`${chalk.blue.bold('Reading accounts.txt...')}`);
      const accounts = (await fs.readFile('accounts.txt', 'utf-8')).split('\n').filter(line => line.trim());
      if (!accounts.length) {
        throw new Error('accounts.txt is empty or contains no valid private keys');
      }
      this.log(`${chalk.green.bold(`Found ${accounts.length} accounts`)}`);
      accounts.forEach((account, index) => {
        this.log(`${chalk.blue.bold(`Account ${index + 1}: ${account.slice(0, 6)}...${account.slice(-6)}`)}`);
      });

      const { captchaService, useProxyChoice, rotate } = await this.printQuestion();
      this.log(`${chalk.green.bold(`Using settings: captchaService=${captchaService}, useProxyChoice=${useProxyChoice}, rotate=${rotate}`)}`);

      while (true) {
        this.log(`${chalk.blue.bold('Starting account processing loop...')}`);
        const useProxy = [1, 2].includes(useProxyChoice);
        this.clearTerminal();
        this.welcome();
        this.log(
          `${chalk.green.bold("Account's Total: ")}` +
          `${chalk.white.bold(accounts.length)}`
        );

        if (useProxy) {
          this.log(`${chalk.blue.bold('Loading proxies...')}`);
          await this.loadProxies(useProxyChoice);
        }

        const separator = '='.repeat(25);
        for (const account of accounts) {
          if (account) {
            this.log(`${chalk.blue.bold(`Processing private key: ${account.slice(0, 6)}...${account.slice(-6)}`)}`);
            const address = this.generateAddress(account);
            if (address) {
              const authToken = this.generateAuthToken(address);
              if (authToken) {
                this.authTokens[address] = authToken;
                this.log(
                  `${chalk.cyan.bold(`${separator}[`)}` +
                  `${chalk.white.bold(` ${this.maskAccount(address)} `)}` +
                  `${chalk.cyan.bold(`]${separator}`)}`
                );
                await this.processAccount(address, useProxy, rotate, captchaService);
                await new Promise(resolve => setTimeout(resolve, 3000));
              } else {
                this.log(`${chalk.red.bold(`Failed to generate auth token for address: ${this.maskAccount(address || account)}`)}`);
              }
            } else {
              this.log(`${chalk.red.bold(`Invalid private key: ${account.slice(0, 6)}...${account.slice(-6)}`)}`);
            }
          } else {
            this.log(`${chalk.red.bold('Empty account entry skipped')}`);
          }
        }

        this.log(`${chalk.cyan.bold('=')}`.repeat(72));
        this.log(`${chalk.blue.bold('All accounts processed, entering wait loop...')}`);
        let seconds = 24 * 60 * 60;
        while (seconds > 0) {
          if (seconds % 300 === 0 || seconds === 24 * 60 * 60) {
            const formattedTime = this.formatSeconds(seconds);
            console.log(
              `${chalk.cyan.bold(`[ Wait for`)}` +
              `${chalk.white.bold(` ${formattedTime} `)}` +
              `${chalk.cyan.bold(`... ]`)}` +
              `${chalk.white.bold(` | `)}` +
              `${chalk.blue.bold(`All Accounts Have Been Processed.`)}`
            );
          }
          await new Promise(resolve => setTimeout(resolve, 1000));
          seconds--;
        }
      }
    } catch (e) {
      this.log(`${chalk.red.bold(`Error in main: ${e.message}`)}`);
      throw e;
    }
  }

  formatSeconds(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
}

(async () => {
  try {
    console.log(chalk.blue.bold('Creating KiteFaucetStake instance...'));
    const bot = new KiteFaucetStake();
    console.log(chalk.blue.bold('Running main function...'));
    await bot.main();
  } catch (e) {
    console.log(
      `${chalk.cyan.bold(`[ ${moment().tz(wib).format('MM/DD/YY HH:mm:ss z')} ]`)}` +
      `${chalk.white.bold(' | ')}` +
      `${chalk.red.bold('[ EXIT ] Kite Faucet & Stake BOT')}`
    );
    console.log(chalk.red.bold(`Final error: ${e.message}`));
  }
})();
