# Secretable

Secretable is a telegram bot for managing passwords and others secrets stored in Google Sheets. Convenient management of your secrets in the messenger. Strong encryption AES256 + PKCS 8 + PBKDF2. Using Google Sheets as storage allows you to track changes, easily make backups, and work without encryption with raw data. Share passwords for other users and chats.

### About security:
- In encrypted mode, Google Sheets do not store any open data other than description.

- In the environment in which the bot is launched, the "salt" is generated and stored, which is necessary for encryption using the master password.

- If the master password is compromised, then this is not enough to decrypt the data, without salt it is impossible to decrypt the stored data.

- When the master password is reset, the salt is re-generated.

- With the master password, not the data is encrypted, but the private key with which this data is encrypted, which allows you to painlessly change the master password without changing or re-encrypting the data.

- The bot works only in pull mode, independently requesting data from Telegram servers, so there is no need to open ports, firewall settings, and exclude influence and vulnerabilities from the http server.

**WARNING:** After resetting the master password, the salt changes, which is stored in the environment variable `ST_SALT`, if the OS reboots, then the variable may disappear and the data will not be able to decrypt. Therefore, in cases of salt changes, we recommend saving the initialization of the environment variable in your OS initialization scripts or in the `--salt` flag when starting the bot.

## Install
To install the bot, just download the binary file of the latest release for your OS from the [releases page](https://github.com/secretable/secretable/releases)

## Getting started
### 1. Generate Google Credentials file to access tables via Google API
- Go to the  [Google Console](https://console.cloud.google.com/)  and create a new project for the bot.
- Then go to the [APIs and Services > Credentials](https://console.cloud.google.com/apis/credentials) section
- Сlick on the **CREATE CREDENTIALS** button and select **Service account**
- Fill in all the required fields and click **DONE**
- In the [APIs and Services > Credentials](https://console.cloud.google.com/apis/credentials)  section in the **Service accounts** list, you will see an email, you will need it to provide access to your  Google Sheets document.
- Go to the settings of your service account in the **KEYS** section and click on the **Add key** button, select **Create new key** with the **JSON** type. Save the file.
- Go to [APIs and Services > Library](https://console.cloud.google.com/apis/library) section and find the Google Sheets API. Click **ENABLE** button.

### 2. Give the bot access to tables
- Create a new document in Google Sheets.
- Click on the **Share** button and add your service account as an editor
- Сopy and save from the address bar of your browser spreadsheet id.
For example URL from address bar: `https://docs.google.com/spreadsheets/d/2EKulKXNueAgLzD7UHYiilwJE27gb4N7sj5eoAGlhr34/edit#gid=0`
Part of the string `2EKulKXNueAgLzD7UHYiilwJE27gb4N7sj5eoAGlhr34` is the spreadsheet id.

### 3. Create a telegram bot.
Connect to the bot [BotFather](https://t.me/BotFather) and use the `/newbot` command to create a bot and save a token to access it.

### 4. Run Secretable
Start the downloaded bot release by specifying flags:<br>
`./secretable -t <telegram_bot_token> -s <spreadsheet_id> -g <path_to_google_credentials_file>`

### 5. Add access
Add your telegram chat id to the table **Access** in the first column.

## Usage
To use, just look at the `--help` command:
```
Usage:
  secretable [OPTIONS]

Application Options:
  -t, --tg_bot_token=       Telegram bot token
  -g, --google_credentials= Path to Google credentials JSON file
  -s, --spreadsheet_id=     Spreadsheet ID
  -c, --cleanup_timeout=    Received and send messages cleanup timeout in seconds (default: 30)
  -u, --unencrypted         Unencrypted mode
      --salt=               Salt for encryption with a master password. Automatically set to environment variable. If not specified, a new one is
                            generated and setted. [$ST_SALT]

Help Options:
  -h, --help                Show this help message
```
