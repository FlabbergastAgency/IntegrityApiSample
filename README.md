# Google Integrity API server side

Showcase server app for handling Play integrity API

## Requirements

- Install required packages `npm install`
- Add `google_app_credentials.json` [google cloud create credentials](https://console.cloud.google.com/apis/credentials?project=worldcoin-android)
- Add `app_info.json` 
    ```
    {
    "package": "com.myapp"
    }
    ```
- Run app `node app.js`

### nonce request
```
curl --location --request GET 'localhost:3000/nonce'
```

### verdict request
```
curl --location --request GET 'localhost:3000/verdict?token={integrity_token_from_adnroid_device}&nonce={nonce}'
```
