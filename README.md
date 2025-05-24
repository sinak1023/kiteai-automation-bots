# KiteAI Automation Bots

Welcome to the **KiteAI Automation Bots** repository! This project provides two powerful Node.js scripts to automate interactions with the KiteAI testnet:
- **Chain Bot** (`chat.js`): Automates blockchain chain interactions, such as transaction signing and chain management.
- **Faucet & Stake Bot** (`faucet.js`): Automates faucet token requests and staking on the KiteAI testnet.

Both scripts support reCAPTCHA v2 solving using CapSolver or 2Captcha, configurable proxy options, and user-friendly CLI prompts. Built for developers and blockchain enthusiasts, these bots streamline KiteAI testnet operations.

## Features

### Chain Bot
- Automates blockchain chain interactions (e.g., transaction signing, chain management).
- Supports reCAPTCHA v2 solving with CapSolver or 2Captcha.
- Configurable proxy options (Monosans, private proxies, or no proxy) with rotation.
- Interactive CLI for selecting CAPTCHA service and proxy settings.

### Faucet & Stake Bot
- Automates:
  - Signing into the KiteAI testnet.
  - Solving reCAPTCHA v2 using CapSolver or 2Captcha.
  - Requesting faucet tokens.
  - Checking account balance.
  - Staking 1 KITE on a randomly selected subnet.
- Configurable delays: 15-20s post-faucet, 3-5s pre-staking.
- Proxy support with automatic rotation for failed attempts.
- Interactive CLI for selecting CAPTCHA service and proxy settings.

## Prerequisites

- **Node.js**: Version 18.20.7 or higher.
- **NPM Packages**:
  ```bash
  npm install axios socks-proxy-agent https-proxy-agent crypto web3@1.10.0 chalk moment-timezone user-agents readline dotenv
  ```
- **API Keys**:
  - CapSolver: Obtain from [CapSolver](https://www.capsolver.com/).
  - 2Captcha: Obtain from [2Captcha](https://2captcha.com/).
- **Accounts File**: A `accounts.txt` file with private keys (one per line).
- **Proxy File** (optional): A `proxy.txt` file with proxy addresses (one per line, format: `host:port` or `user:password@host:port`).

## Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/sinak1023/kiteai-automation-bots.git
   cd kiteai-automation-bots
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment**:
   Create a `.env` file in the project root:
   ```bash
   nano .env
   ```
   Add your API keys:
   ```
   CAPSOLVER_API_KEY=your_capsolver_api_key
   TWOCAPTCHA_API_KEY=your_2captcha_api_key
   ```
   Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

4. **Prepare Accounts**:
   Create `accounts.txt` with your private keys:
   ```bash
   nano accounts.txt
   ```
   Example:
   ```
   2b6834...7ab6bb
   ```
   Save and exit.

5. **Prepare Proxies** (optional):
   If using proxies, create `proxy.txt`:
   ```bash
   nano proxy.txt
   ```
   Example:
   ```
   99.992.99.197:3999
   ```
   Save and exit.

## Usage

### Running the Chain Bot
Execute the chain bot script:
```bash
node chat.js
```
- **Prompts**:
  - Choose CAPTCHA service: `1` for CapSolver, `2` for 2Captcha.
  - Choose proxy option: `1` for Monosans, `2` for private proxies, `3` for no proxy.
  - Rotate proxies: `y` to rotate on failure, `n` to skip.
- The bot automates chain interactions, solving reCAPTCHAs as needed.

### Running the Faucet & Stake Bot
Execute the faucet and stake script:
```bash
node faucet.js
```
- **Prompts**:
  - Choose CAPTCHA service: `1` for CapSolver, `2` for 2Captcha.
  - Choose proxy option: `1` for Monosans, `2` for private proxies, `3` for no proxy.
  - Rotate proxies: `y` to rotate on failure, `n` to skip.
- The bot signs in, solves reCAPTCHAs, requests faucet tokens, waits 15-20s, checks balance, and stakes 1 KITE, looping every 24 hours.

## Example Output
### Chain Bot
```
[ 05/24/25 21:XX:XX WIB ] | Processing chain for address: 0xb991******181B70
[ 05/24/25 21:XX:XX WIB ] | Solving Google reCAPTCHA v2 with 2Captcha...
[ 05/24/25 21:XX:XX WIB ] | reCAPTCHA solved successfully: 03AFcWeA...
[ 05/24/25 21:XX:XX WIB ] | Chain interaction completed successfully
```

### Faucet & Stake Bot
```
[ 05/24/25 21:XX:XX WIB ] | =========================[ 0xb991******181B70 ]=========================
[ 05/24/25 21:XX:XX WIB ] | Solving Google reCAPTCHA v2 with 2Captcha...
[ 05/24/25 21:XX:XX WIB ] | reCAPTCHA solved successfully: 03AFcWeA...
[ 05/24/25 21:XX:XX WIB ] | Faucet requested successfully for address: 0xb991******181B70
[ 05/24/25 21:XX:XX WIB ] | Waiting 17.5 seconds before proceeding...
[ 05/24/25 21:XX:XX WIB ] | Balance for 0xb991******181B70: 1.01 KITE
[ 05/24/25 21:XX:XX WIB ] | tx_hash: 0x2bbf7f185282f969a4e4f02b59e242b2e...
```

## Troubleshooting
- **CAPTCHA Errors**: Verify API keys and account balance on CapSolver/2Captcha. Ensure `proxy.txt` has valid proxies.
- **Proxy Issues**: Test proxies with `curl --proxy http://45.202.76.137:3129 https://www.google.com`.
- **Network Issues**: Ensure internet connectivity with `ping google.com`.
- **Logs**: Check console output for detailed error messages.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## Support
For questions or issues, join my Telegram channel: [OstadKachal](https://t.me/ostadkachal).

## Buy Me a Coffee
If you find this project helpful, consider supporting me with a coffee on the Base network:
- **Base Address**: `0x7A43342707de2FA07b0C4cCe132dFD49fdA2a711`



---

Created by [sinak1023](https://github.com/sinak1023).
