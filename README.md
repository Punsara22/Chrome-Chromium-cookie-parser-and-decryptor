# About

The CLI tool which can extract cookies from Cookie file and decrypt them using Windows Data Protection API (DPAPI)

# Usage

TODO

# Dependecies (Nugget)

- Microsoft.Data.Sqlite (6.0.4 or higher)
- System.Security.Cryptography.ProtectedData (6.0.0 or higher)

# Explanation

Chromium-based browser cookies are stored inside a file named `Cookies`, which is an SQLite database.
File path depends on browser version:
- `...\User Data\Default\Network` — for modern engines since 2022.
- `...\User Data\Default\` — old version.

Chromium cookies DB has 2 columns for storing values: `value` and `encrypted_value`, the latter one being used when the cookie stored was requested to be encrypted. Often the case with certain confidential information and long-time session keys.

Chromium uses triple DES encryption with the current users password as seed on windows machines. In order to decrypt this in C#, one should use Windows Data Protection API (DPAPI), otherwise you can't decrypt your cookie file cause of masterkey.

# Other stuff

If you are obsessed with cookies, you should also look YT-DLP cookies module code: https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/cookies.py
