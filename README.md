# About

The CLI tool which can extract cookies from Cookie file and decrypt them using Windows Data Protection API (DPAPI).

# Usage

Usage: `CookiesDecryptor.exe` `<path>` `<method>` `[argument]`

Path is a directory path, depends on method.

Available methods:<br/>
- `decrypt` — decrypts Cookie file at user profile path in `<path>\Default\Network\Cookie` and saves them to `Cookies_json.txt`, `Cookies_http.txt`, `Cookies_netscape.txt` files at `<path>` directory.<br/>
- `decrypt-show` — same as decrypt, but also types out all decoded cookies.<br/>
- `decrypt-profiles` — decrypts Cookie files in all profile folder in '<path>' directory and saves them to files as above but at <path>\<profile> folder. Use it when you got a lot of user profiles in 1 directory.<br/>
- `decrypt-profiles-show` — same as decrypt-profiles, but also types out all decoded cookies.<br/>
- `[decrypt|decrypt-show|decrypt-profiles|decrypt-profiles-show]` `<filterWord>`  - same as above, but also filters cookie's host by mask `*filterWord*`.

# Explanation & How it works

Chromium-based browser store cookies in an encrypted SQLite database in file named `Cookie`. File path depends on browser version. Here are some examples.

- On Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` (encrypted with [DPAPI — Windows Data Protection API](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)). Old versions below 2022 used path `...\Chrome\User Data\Default\Cookies`.
- On macOS: `/Library/Application Support/Google/Chrome/Default/Cookies` (protected by TCC).

Chromium cookies DB has 2 columns for storing values: `value` and `encrypted_value`, the latter one being used when the cookie stored was requested to be encrypted with [DPAPI](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection). It is noteworthy that Microsoft themselves say that [DPAPI isn't intended for use in web apps](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction?view=aspnetcore-9.0#:~:text=The%20Windows%20data%20protection%20API%20%28DPAPI%29%20isn%27t%20intended%20for%20use%20in%20web%20apps). Chromium uses triple encryption with the current users password as seed on windows machines. In order to decrypt AES key in C#, you should use [DPAPI](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) or have DPAPI Master Key, otherwise you can't decrypt your local cookie file.

So the steps are:
1. Access the cookie database and the encryption key (e.g., the AES key in the `Local State` file on Windows which is located at `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`).
2. Decrypt the AES key using DPAPI or get the DPAPI Master Key from `C:\Users\...\AppData\Roaming\Microsoft\Protect` (google about `CREDHIST` / `SYNCHIST` and their value in the OS).

DPAPI ties encryption to the **user profile and machine**, so you need to decrypt AES key on the same machine where it was encoded.

# Dependecies 

- .Net 8 for compiling. **Compiled binaries in release already contains all .Net libraries.** 
- Nugget: Microsoft.Data.Sqlite (6.0.4 or higher). Tested on 9.0.8.
- Nugget: System.Security.Cryptography.ProtectedData (6.0.0 or higher). Tested on 9.0.8.

# Notes, other stuff and sources

If you got an exception `0x8009000b: Key not valid for use in specific state`, that means you can't decrypt this AES key on your machine.

- Full explanation: https://fpt-is.com/en/insights/cookie-bite-chrome-attack-steals-session/#:~:text=Decrypting%20Locally%20Stored%20Cookies
- Google Blog about impoving cookies (Jul 30, 2024): https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
- If you are obsessed with cookies, you should also look YT-DLP cookies module code: https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/cookies.py

# Todo
- Check if Local State file is valid.
- Check if Cookies db file is exists. 
