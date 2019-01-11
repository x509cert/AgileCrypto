using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace AgileCrypto_PoC
{
    public class AgileCrypto
    {
        #region Constants and internal vars

        // constants used to create the crypto blob, format is:
        //   PBKDF info
        //   Symmetric alg info
        //   HMAC alg info
        //   ciphertext in base64
        //   HMAC in base64
        private const char Delim = '|';
        private const int LinePbkdfsettings = 0;
        private const int LineSymalgsettings = 1;
        private const int LineHmacsettings = 2;
        private const int LineCiphertext = 3;
        private const int LineHmac = 4;
        private const string Crlf = "\r\n";

        // default crypto config data, format is:
        //   PBKDF info
        //   Symmetric alg info
        //   HMAC alg info
        private string[] _configData;

        // the crypto data
        private SymmetricAlgorithm _sym;
        private Rfc2898DeriveBytes _pbkdf;
        private HMAC _hmac;
        private byte[] _salt = new byte[32];

        #endregion

        #region CTORs

        public AgileCrypto()
        {
            string[] config = File.ReadAllLines("crypto.config");
            Init(config);
        }

        public AgileCrypto(string[] config)
        {
            Init(config);
        }

        private void Init(string[] config)
        {
            _configData = config;
        }

        #endregion 

        #region Encrypt, Decrypt & HMAC Helpers

        /// <summary>
        ///     Delegate function to convert objects to bytes
        /// </summary>
        /// <param name="o">Object to convert</param>
        /// <returns>Byte value of object</returns>
        private byte ObjToByte(object o) => Convert.ToByte(o);

        /// <summary>
        /// Removes the key from a JSON string
        /// </summary>
        /// <param name="json">JSON input</param>
        /// <returns>Cleansed string</returns>
        private static string RemoveKeyFromJson(string json)
        {
            return (new Regex("\"Key\":\\[.+?\\],", RegexOptions.None)).Replace(json, "");
        }

        private const string INDENT_STRING = "    ";

        /// <summary>
        /// Beutifies JSON
        /// </summary>
        /// <param name="json"></param>
        /// <returns></returns>
        static string FormatJson(string json)
        {
            int indentation = 0;
            int quoteCount = 0;
            var result =
                from ch in json
                let quotes = ch == '"' ? quoteCount++ : quoteCount
                let lineBreak = ch == ',' && quotes % 2 == 0 ? ch + Environment.NewLine + String.Concat(Enumerable.Repeat(INDENT_STRING, indentation)) : null
                let openChar = ch == '{' || ch == '[' ? ch + Environment.NewLine + String.Concat(Enumerable.Repeat(INDENT_STRING, ++indentation)) : ch.ToString()
                let closeChar = ch == '}' || ch == ']' ? Environment.NewLine + String.Concat(Enumerable.Repeat(INDENT_STRING, --indentation)) + ch : ch.ToString()
                select lineBreak == null
                            ? openChar.Length > 1
                                ? openChar
                                : closeChar
                            : lineBreak;

            return String.Concat(result);
        }

        /// <summary>
        /// Encrypt some plaintext using various member vars
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt</param>
        /// <returns>Ciphertext as Base64 string</returns>
        private string Encrypt(string plaintext)
        {
            var memStream = new MemoryStream();
            var cryptoStram = new CryptoStream(memStream, _sym.CreateEncryptor(_sym.Key, _sym.IV),
                CryptoStreamMode.Write);
            byte[] data = Encoding.ASCII.GetBytes(plaintext);
            cryptoStram.Write(data, 0, data.Length);
            cryptoStram.FlushFinalBlock();

            return Convert.ToBase64String(memStream.ToArray());
        }

        /// <summary>
        /// Decrypts ciphertext using various member vars
        /// </summary>
        /// <param name="ciphertext">Ciphertext in base64 format</param>
        /// <returns>Plaintext</returns>
        private string Decrypt(string ciphertext)
        {
            var memStream = new MemoryStream();
            var cryptoStram = new CryptoStream(memStream, _sym.CreateDecryptor(_sym.Key, _sym.IV),
                CryptoStreamMode.Write);
            byte[] data = Convert.FromBase64String(ciphertext);
            cryptoStram.Write(data, 0, data.Length);
            cryptoStram.FlushFinalBlock();

            byte[] decrypted = memStream.ToArray();

            return Encoding.ASCII.GetString(decrypted, 0, decrypted.Length);
        }

        /// <summary>
        /// Get's the HMAC for some ciphertext. Note *CIPHERTEXT* not *PLAINTEXT*
        /// There have been debates for years about encrypt-then-MAC vs MAC-then-encrypt
        /// I chose the former with the belief that verifying the data has not been
        /// tampered with before attempting the ensuing decryption is safer.
        /// </summary>
        /// <param name="ciphertext">String of ciphertext</param>
        /// <returns>string</returns>
        private string CalculateHmac(string ciphertext)
        {
            byte[] hmac = _hmac.ComputeHash(Encoding.ASCII.GetBytes(ciphertext));
            return Convert.ToBase64String(hmac.ToArray());
        }

        #endregion

        #region Encrypt and Decrypt Core Functions

        /// <summary>
        /// Encrypts and MACs some plaintext with a passphrase
        /// </summary>
        /// <param name="passphrase">Password to encrypt/MAC</param>
        /// <param name="plaintext">Text to protect</param>
        /// <returns>Base64 ciphertext blob</returns>
        public string EncryptAndMac(string passphrase, string plaintext)
        {
            if (passphrase.Length == 0 || plaintext.Length == 0)
                throw new ArgumentException();

            // generate a salt from random data (24 bytes) + system tick count (8 bytes)
            byte[] ticks = BitConverter.GetBytes(DateTime.Now.Ticks);
            var tempSalt = new byte[_salt.Length - ticks.Length];
            new RNGCryptoServiceProvider().GetBytes(tempSalt);
            Array.Copy(tempSalt, _salt, tempSalt.Length);
            Array.Copy(ticks, 0, _salt, tempSalt.Length, ticks.Length);

            // get PBKDF  info and create object (salt is ignored from config file)
            string s = _configData[LinePbkdfsettings].Split(Delim)[1];
            dynamic dp = new JavaScriptSerializer().DeserializeObject(s);
            int iter = int.Parse(dp["IterationCount"].ToString());
            _pbkdf = new Rfc2898DeriveBytes(passphrase, _salt, iter);

            // get symmetric cipher info and create object
            _sym = SymmetricAlgorithm.Create(_configData[LineSymalgsettings].Split(Delim)[0]);
            dynamic ds = new JavaScriptSerializer().
                DeserializeObject(_configData[LineSymalgsettings].Split(Delim)[1]);

            _sym.BlockSize = ds["BlockSize"];
            _sym.KeySize = ds["KeySize"];
            _sym.Mode = (CipherMode) ds["Mode"];
            _sym.Padding = (PaddingMode) ds["Padding"];

            // get HMAC settings and create object
            // TODO: currently uses default alg (SHA-256), need to make it configurable, too
            _hmac = HMAC.Create(_configData[LineHmacsettings].Split(Delim)[0]);

            //
            // Do the dirty work
            //

            // generate symmetric key and HMAC key
            _sym.Key = _pbkdf.GetBytes(_sym.KeySize >> 3);
            _hmac.Key = _pbkdf.GetBytes(_hmac.HashSize >> 3);

            // perform the crypto opertions
            string ciphertext = Encrypt(plaintext);
            
            // encrypt then MAC - this MACs the ciphertext
            string hmac = CalculateHmac(ciphertext);

            // serialize the symmetric alg, but strip out the key
            var oSerializer = new JavaScriptSerializer();

            // clear all keys
            //_sym.Key = new byte[_sym.Key.Length];
            //_hmac.Key = new byte[_hmac.Key.Length];

            // serialize the ciphertext/HMAC/PKBDF
            string sJsonSym = FormatJson(RemoveKeyFromJson(oSerializer.Serialize(_sym)));
            string sJsonHmac = FormatJson(RemoveKeyFromJson(oSerializer.Serialize(_hmac)));
            string sJsonPbkdf = FormatJson(oSerializer.Serialize(_pbkdf));

            // build the resulting cipherblob string
            var sb = new StringBuilder();
            sb.Append(_pbkdf.ToString() + Delim + sJsonPbkdf + Crlf);
            sb.Append(_sym.ToString() + Delim + sJsonSym + Crlf);
            sb.Append(_hmac.ToString() + Delim + sJsonHmac + Crlf);
            sb.Append(ciphertext + Crlf);
            sb.Append(hmac);

            return sb.ToString();
        }

        /// <summary>
        /// Verifies a MAC and then decrypts a ciphertext blob
        /// </summary>
        /// <param name="passphrase">Password to encrypt/MAC</param>
        /// <param name="blob">Ciphertext blob</param>
        /// <returns>Decrypted data (assuming MAC is ok)</returns>
        public string VerifyAndDecrypt(string passphrase, string blob)
        {
            if (passphrase.Length == 0 || blob.Length == 0)
                throw new ArgumentException();

            // pull the data from the crypto blob. 
            // format is:
            //   PBKDF info
            //   Symmetric alg info
            //   HMAC alg info
            //   ciphertext in base64
            //   HMAC in base64
            string[] delims = new string[] {Crlf};
            string[] data = blob.Split(delims, StringSplitOptions.RemoveEmptyEntries);

            string jsonPbkdf = data[LinePbkdfsettings].Split(Delim)[1];
            string jsonSym = data[LineSymalgsettings];
            string jsonHmac = data[LineHmacsettings];

            string ciphertext = data[LineCiphertext];
            string hMac = data[LineHmac];

            dynamic dp = new JavaScriptSerializer().DeserializeObject(jsonPbkdf);
            int iter = int.Parse(dp["IterationCount"].ToString());
            _salt = Array.ConvertAll(dp["Salt"], new Converter<object, byte>(ObjToByte));
            _pbkdf = new Rfc2898DeriveBytes(passphrase, _salt, iter);

            // get symmetric cipher info and create object
            _sym = SymmetricAlgorithm.Create(jsonSym.Split(Delim)[0]);
            dynamic ds = new JavaScriptSerializer().DeserializeObject(jsonSym.Split(Delim)[1]);
            _sym.BlockSize = ds["BlockSize"];
            _sym.KeySize = ds["KeySize"];
            _sym.Mode = (CipherMode)ds["Mode"];
            _sym.Padding = (PaddingMode)ds["Padding"];
            _sym.IV = Array.ConvertAll(ds["IV"], new Converter<object, byte>(ObjToByte));

            // get HMAC settings and create object
            // TODO: currently uses default alg, need to make it configurable, too
            _hmac = HMAC.Create(jsonHmac.Split(Delim)[0]);

            // derive symmetric key and HMAC key
            // key is generated from passphrase using a PBKDF
            _sym.Key = _pbkdf.GetBytes(_sym.KeySize >> 3);
            _hmac.Key = _pbkdf.GetBytes(_hmac.HashSize >> 3);

            // compare HMAC in blob with calulated HMAC
            string newMac = CalculateHmac(ciphertext);
            if (!String.Equals(newMac, hMac))
                throw new CryptographicException("Incorrect HMAC");

            return Decrypt(ciphertext);
        }

        #endregion
    }
}