# About

The CLI tool which can extract cookies from Cookie file and decrypt them using Windows Data Protection API (DPAPI)

# Usage

TODO

# Dependecies (Nugget)

- Microsoft.Data.Sqlite (6.0.4 or higher)
- System.Security.Cryptography.ProtectedData (6.0.0 or higher)

# Explanation

Chromium-based browser store cookies in an encrypted SQLite database in file named `Cookie`. File path depends on browser version. Here are some examples.

- On Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` (encrypted with DPAPI — Windows Data Protection API). Old versions below 2022 used path `...\Chrome\User Data\Default\Cookies`.
- On macOS: `/Library/Application Support/Google/Chrome/Default/Cookies` (protected by TCC).

Chromium cookies DB has 2 columns for storing values: `value` and `encrypted_value`, the latter one being used when the cookie stored was requested to be encrypted with Windows Data Protection API (DPAPI). Often the case with certain confidential information and long-time session keys. Chromium uses triple DES encryption with the current users password as seed on windows machines. In order to decrypt this in C#, you should use DPAPI, otherwise you can't decrypt your cookie file cause of wrong masterkey.

So the steps are:
1. Access the cookie database and the encryption key (e.g., the AES key in the `Local State` file on Windows which is located at `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`).
2. Decrypt the AES key using DPAPI or get the DPAPI Master Key from `C:\Users\...\AppData\Roaming\Microsoft\Protect` (google about `CREDHIST` / `SYNCHIST` and their value in the OS).

DPAPI ties encryption to the **user profile and machine**, so you need to decrypt AES key on the same machine where it was encoded.

# Other stuff and source

- Full explanation: https://fpt-is.com/en/insights/cookie-bite-chrome-attack-steals-session/#:~:text=Decrypting%20Locally%20Stored%20Cookies
- Google Blog about impoving cookies (Jul 30, 2024): https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
- If you are obsessed with cookies, you should also look YT-DLP cookies module code: https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/cookies.py
