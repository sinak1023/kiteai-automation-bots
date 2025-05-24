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

const wib = 'Asia/Jakarta';

class KiteAi {
  constructor() {
    console.log(chalk.blue.bold('Initializing KiteAi class...'));
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
    this.userInteractions = {};
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
      `${chalk.green.bold('Auto BOT Kite by ostadkachal\n')}`
    );
  }

  formatSeconds(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
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

  generateQuizTitle() {
    return `daily_quiz_${moment().format('YYYY-MM-DD')}`;
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

  questionLists(agentName) {
    if (agentName === 'Professor') {
      return [
        'What is Kite AI\'s core technology?',
        'What is proof of AI?'
      ];
    } else if (agentName === 'Crypto Buddy') {
      return [
        'What is Bitcoin\'s current price?'
      ];
    } else if (agentName === 'Sherlock') {
      return [
        'What do you think of this transaction? 0x252c02bded9a24426219248c9c1b065b752d3cf8bedf4902ed62245ab950895b'
      ];
    }
    return [];
  }

  agentLists(agentName) {
    try {
      this.log(`${chalk.blue.bold(`Generating agent list for: ${agentName}`)}`);
      const agentLists = {};
      if (agentName === 'Professor') {
        agentLists.service_id = 'deployment_KiMLvUiTydioiHm7PWZ12zJU';
        agentLists.title = agentName;
        agentLists.message = this.questionLists(agentName)[Math.floor(Math.random() * this.questionLists(agentName).length)];
      } else if (agentName === 'Crypto Buddy') {
        agentLists.service_id = 'deployment_ByVHjMD6eDb9AdekRIbyuz14';
        agentLists.title = agentName;
        agentLists.message = this.questionLists(agentName)[Math.floor(Math.random() * this.questionLists(agentName).length)];
      } else if (agentName === 'Sherlock') {
        agentLists.service_id = 'deployment_OX7sn2D0WvxGUGK8CTqsU5VJ';
        agentLists.title = agentName;
        agentLists.message = this.questionLists(agentName)[Math.floor(Math.random() * this.questionLists(agentName).length)];
      }
      this.log(`${chalk.green.bold(`Agent list generated for: ${agentName}`)}`);
      return agentLists;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to generate agent list: ${e.message}`)}`);
      return null;
    }
  }

  generateInferencePayload(serviceId, question) {
    return {
      service_id: serviceId,
      subnet: 'kite_ai_labs',
      stream: true,
      body: {
        stream: true,
        message: question
      }
    };
  }

  generateReceiptPayload(address, serviceId, question, answer) {
    return {
      address,
      service_id: serviceId,
      input: [{ type: 'text/plain', value: question }],
      output: [{ type: 'text/plain', value: answer }]
    };
  }

  maskAccount(account) {
    return account.slice(0, 6) + '*'.repeat(6) + account.slice(-6);
  }

  async agentInference(address, serviceId, question, proxy) {
    const url = `${this.OZONE_API}/agent/inference`;
    const data = this.generateInferencePayload(serviceId, question);
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'Content-Type': 'application/json',
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for inference: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.startsWith('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.post(url, data, config);
      this.log(`${chalk.green.bold(`Inference successful for question: ${question}`)}`);
      return response.data?.output?.value || 'No answer received';
    } catch (e) {
      this.log(`${chalk.red.bold(`Inference failed for question: ${question} - ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return null;
    }
  }

  async submitReceipt(address, serviceId, question, answer, proxy) {
    const url = `${this.NEO_API}/submit_receipt`;
    const data = this.generateReceiptPayload(address, serviceId, question, answer);
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'Content-Type': 'application/json',
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for submit_receipt: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.startsWith('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.post(url, data, config);
      this.log(`${chalk.green.bold(`Receipt submitted successfully for question: ${question}`)}`);
      return response.data?.data?.id || null;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to submit receipt for question: ${question} - ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return null;
    }
  }

  async getInferenceTxHash(address, inferenceId, proxy) {
    const url = `https://neo.prod.gokite.ai/v1/inference?id=${inferenceId}`;
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'User-Agent': this.getUserAgent()
    };
    try {
      const config = { headers, timeout: 60000 };
      if (proxy) {
        this.log(`${chalk.blue.bold(`Using proxy for get_inference: ${proxy}`)}`);
        const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
        if (proxyUrl.startsWith('socks')) {
          config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
        } else {
          config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
        }
      }
      const response = await axios.get(url, config);
      const txHash = response.data?.data?.tx_hash || '';
      if (txHash) {
        this.log(`${chalk.green.bold(`tx_hash: ${txHash}`)}`);
      }
      return txHash;
    } catch (e) {
      this.log(`${chalk.red.bold(`Failed to get inference tx_hash for ID ${inferenceId}: ${e.message}`)}`);
      if (e.response) {
        this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
      }
      return '';
    }
  }

  async printQuestion() {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const question = (query) => new Promise(resolve => rl.question(query, resolve));

    this.log(`${chalk.blue.bold('Starting user input collection...')}`);
    let choose;
    while (true) {
      console.log(`${chalk.white.bold('1. Run With Monosans Proxy')}`);
      console.log(`${chalk.white.bold('2. Run With Private Proxy')}`);
      console.log(`${chalk.white.bold('3. Run Without Proxy')}`);
      choose = parseInt(await question(`${chalk.blue.bold('Choose [1/2/3] -> ')}`));
      if ([1, 2, 3].includes(choose)) {
        const proxyType = choose === 1 ? 'Run With Monosans Proxy' : choose === 2 ? 'Run With Private Proxy' : 'Run Without Proxy';
        this.log(`${chalk.green.bold(`${proxyType} Selected.`)}`);
        break;
      } else {
        this.log(`${chalk.red.bold('Please enter either 1, 2 or 3.')}`);
      }
    }

    let rotate = false;
    if ([1, 2].includes(choose)) {
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

    let count;
    while (true) {
      count = parseInt(await question(`${chalk.yellow.bold('How Many Times Would You Like to Interact With Kite AI Agents? -> ')}`));
      if (count > 0) {
        break;
      } else {
        this.log(`${chalk.red.bold('Please enter a positive number.')}`);
      }
    }

    rl.close();
    this.log(`${chalk.green.bold(`User input collected: interactCount=${count}, useProxyChoice=${choose}, rotate=${rotate}`)}`);
    return { interactCount: count, useProxyChoice: choose, rotate };
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
          if (proxyUrl.startsWith('socks')) {
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

  async userData(address, proxy, retries = 5) {
    const url = `${this.OZONE_API}/me`;
    const headers = {
      ...this.headers,
      'Authorization': `Bearer ${this.accessTokens[address]}`,
      'User-Agent': this.getUserAgent()
    };
    this.log(`${chalk.blue.bold(`Fetching user data for address: ${this.maskAccount(address)}`)}`);
    await new Promise(resolve => setTimeout(resolve, 3000));
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const config = { headers, timeout: 60000 };
        if (proxy) {
          this.log(`${chalk.blue.bold(`Using proxy: ${proxy}`)}`);
          const proxyUrl = proxy.startsWith('http://') || proxy.startsWith('https://') ? proxy : `http://${proxy}`;
          if (proxyUrl.startsWith('socks')) {
            config.httpsAgent = new SocksProxyAgent(proxyUrl, { rejectUnauthorized: false });
          } else {
            config.httpsAgent = new HttpsProxyAgent(proxyUrl, { rejectUnauthorized: false });
          }
        }
        const response = await axios.get(url, config);
        this.log(`${chalk.green.bold(`User data fetched successfully for address: ${this.maskAccount(address)}`)}`);
        return response.data;
      } catch (e) {
        this.log(`${chalk.red.bold(`User data fetch attempt ${attempt + 1} failed: ${e.message}`)}`);
        if (e.response) {
          this.log(`${chalk.red.bold(`Server response: ${JSON.stringify(e.response.data)}`)}`);
        }
        if (attempt < retries - 1) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          continue;
        }
        return null;
      }
    }
    this.log(`${chalk.red.bold(`User data fetch failed after ${retries} attempts for address: ${this.maskAccount(address)}`)}`);
    return null;
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

  async processAccounts(address, interactCount, useProxy, rotate) {
    this.log(`${chalk.blue.bold(`Processing account: ${this.maskAccount(address)}`)}`);
    const signed = await this.processUserSignin(address, useProxy, rotate);
    if (signed) {
      const proxy = useProxy ? this.getNextProxyForAccount(address) : null;
      this.log(
        `${chalk.cyan.bold('Proxy     :')}` +
        `${chalk.white.bold(` ${proxy || 'None'} `)}`
      );

      const user = await this.userData(address, proxy);
      if (!user) {
        this.log(
          `${chalk.cyan.bold('Status    :')}` +
          `${chalk.red.bold(' GET User Data Failed ')}`
        );
        return;
      }

      const username = user.data?.profile?.username || 'Unknown';
      const saAddress = (user.data?.profile?.smart_account_address || 'Undifined').toUpperCase();
      const balance = user.data?.profile?.total_xp_points || 0;

      this.log(
        `${chalk.cyan.bold('Username  :')}` +
        `${chalk.white.bold(` ${username} `)}`
      );
      this.log(
        `${chalk.cyan.bold('SA Address:')}` +
        `${chalk.white.bold(` ${saAddress} `)}`
      );
      this.log(
        `${chalk.cyan.bold('Balance   :')}` +
        `${chalk.white.bold(` ${balance} XP `)}`
      );
      this.log(`${chalk.cyan.bold('AI Agents :')}`);

      this.userInteractions[address] = 0;

      while (this.userInteractions[address] < interactCount) {
        this.log(
          `${chalk.magenta.bold('  ● ')}` +
          `${chalk.blue.bold('Interactions')}` +
          `${chalk.white.bold(` ${this.userInteractions[address] + 1} of ${interactCount} `)}`
        );

        const agentNames = ['Professor', 'Crypto Buddy', 'Sherlock'];
        const agents = this.agentLists(agentNames[Math.floor(Math.random() * agentNames.length)]);
        if (agents) {
          const { service_id, title: agentName, message: question } = agents;
          this.log(
            `${chalk.cyan.bold('    Agent Name:')}` +
            `${chalk.white.bold(` ${agentName}`)}`
          );
          this.log(
            `${chalk.cyan.bold('    Question  :')}` +
            `${chalk.white.bold(` ${question}`)}`
          );

          // Step 1: Send question to /agent/inference
          const answer = await this.agentInference(address, service_id, question, proxy);
          if (!answer) {
            this.log(`${chalk.red.bold(`Skipping interaction due to inference failure`)}`);
            break;
          }

          // Step 2: Submit receipt to /submit_receipt
          const inferenceId = await this.submitReceipt(address, service_id, question, answer, proxy);
          if (!inferenceId) {
            this.log(`${chalk.red.bold(`Skipping interaction due to receipt submission failure`)}`);
            break;
          }

          // Step 3: Get tx_hash from /inference
          let txHash = '';
          while (!txHash) {
            txHash = await this.getInferenceTxHash(address, inferenceId, proxy);
            if (!txHash) {
              this.log(`${chalk.yellow.bold(`tx_hash is empty, retrying in 20 seconds...`)}`);
              await new Promise(resolve => setTimeout(resolve, 20000));
            }
          }

          this.userInteractions[address]++;
        } else {
          this.log(`${chalk.red.bold(`Failed to generate agent for interaction ${this.userInteractions[address] + 1}`)}`);
          break;
        }
      }

      this.userInteractions[address] = 0;
    }
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

      const { interactCount, useProxyChoice, rotate } = await this.printQuestion();
      this.log(`${chalk.green.bold(`Using settings: interactCount=${interactCount}, useProxyChoice=${useProxyChoice}, rotate=${rotate}`)}`);

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
                await this.processAccounts(address, interactCount, useProxy, rotate);
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
        let seconds = 24 * 60 * 60; // 24 hours
        while (seconds > 0) {
          if (seconds % 300 === 0 || seconds === 24 * 60 * 60) { // Log every 5 minutes
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
}

(async () => {
  try {
    console.log(chalk.blue.bold('Creating KiteAi instance...'));
    const bot = new KiteAi();
    console.log(chalk.blue.bold('Running main function...'));
    await bot.main();
  } catch (e) {
    console.log(
      `${chalk.cyan.bold(`[ ${moment().tz(wib).format('MM/DD/YY HH:mm:ss z')} ]`)}` +
      `${chalk.white.bold(' | ')}` +
      `${chalk.red.bold('[ EXIT ] Kite Ai Ozone - BOT')}`
    );
    console.log(chalk.red.bold(`Final error: ${e.message}`));
  }
})();
