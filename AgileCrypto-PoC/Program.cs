using System;
using System.IO;
using System.Security.Cryptography;
using AgileCrypto_PoC;

internal class Test
{
    private static void Usage()
    {
        Console.WriteLine("Usage for Agile Crypto v1.51");
        Console.WriteLine("\t ACrypto encrypt <passphrase> <plaintext>");
        Console.WriteLine("\t ACrypto decrypt <passphrase> <filename>");
        Environment.Exit(-1);
    }

    /// <summary>
    ///     Main entry point - nothing much to say :)
    /// </summary>
    /// <param name="args"></param>
    private static void Main(string[] args)
    {
        if (args.Length == 3)
        {
            if (args[0].ToLower()[0] == 'e')
            {
                string plaintext = args[2];
                string pass = args[1];

                AgileCrypto ac = new AgileCrypto();
                Console.WriteLine(ac.EncryptAndMac(pass, plaintext));
            } 
            else if (args[0].ToLower()[0] == 'd')
            {
                string pass = args[1];
                string protectedBlob = File.ReadAllText(args[2]);

                AgileCrypto ac = new AgileCrypto();
                try
                {
                    Console.WriteLine(ac.VerifyAndDecrypt(pass, protectedBlob));
                } 
                catch (CryptographicException e)
                {
                    Console.WriteLine("ERR! " + e.Message);
                }
            }
            else
            {
                Usage();
            }
        }
        else
        {
            Usage();
        }
    }
}