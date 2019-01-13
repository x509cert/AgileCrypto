# AgileCrypto
A Proof of Concept for more agile crypto

Michael Howard ([mikehow@microsoft.com](mailto:mikehow@microsoft.com))

Jan 11, 2019

The provided code is a simple proof concept that demonstrates how to be more agile when building applications that use crypto. In this proof of concept, three aspects are demonstrated:

- Agile password-based key derivation
- Agile symmetric encryption
- Agile message authentication codes

Again, remember, this is a proof of concept only to get people thinking about the issue, any suggestions or improvements are welcome.

If you are not aware of what agile crypto is, please read Bryan Sullivan&#39;s intro to the topic at [http://msdn.microsoft.com/en-us/magazine/ee321570.aspx](http://msdn.microsoft.com/en-us/magazine/ee321570.aspx).

# High level operation

The code can either encrypt &amp; MAC some plaintext or verify the MAC &amp; decrypt some ciphertext. When encrypting, the proof of concept code takes a small config file containing crypto policy (named crypto.config) and uses this to encrypt and MAC a string of data. The results of the crypto operations are then displayed on the screen and can be redirected to a file if needed.

When decrypting, if the MAC over the ciphertext check fails, the data is not decrypted and an exception is raised.

# Assumptions &amp; Limitations

- A basic understanding of crypto is assumed.
- The code uses .NET 4.x and the appropriate libraries are already installed on the user&#39;s machine.
- The code has not been tested with every possible combination of symmetric cipher x block mode x key size x padding mode.
- The class names are .NET specific – this could not allow interop with Java or Python.
- The code is not particularly robust, it&#39;s a PoC!
- The code assumes there&#39;s a class factory that allows crypto objects to be created at runtime based on their names.
- The code only works with symmetric algs.
- The code is designed to protect small amounts of data.

# Crypto Config file

The format of the config file is very simple, it&#39;s three lines of text (not XML,) the lines are:

- PBKDF class settings
- Symmetric key algorithm settings
- HMAC algorithm settings

A sample config file looks like this:

System.Security.Cryptography.Rfc2898DeriveBytes|{&quot;IterationCount&quot;:10000}

System.Security.Cryptography.AesCryptoServiceProvider|{&quot;KeySize&quot;:128,&quot;BlockSize&quot;:128,&quot;FeedbackSize&quot;:8,&quot;Mode&quot;:1,&quot;Padding&quot;:2}

System.Security.Cryptography.HMACSHA256|{&quot;HashName&quot;:&quot;SHA256&quot;,&quot;HashSize&quot;:256}

Note the first part of each line (before the &#39;|&#39;) is the name of the class to create at runtime, and the second half are JSON representations of class members. Some class members are missing as they are populated at runtime when the class is instantiated.

# Demo

The following is a series of steps to demo the functionality.

-Open the SLN file and rebuild the solution.

-Navigate to the debug folder.

-Type the following:

`acrypto`

And you should see usage requirements:

If you see errors about missing assemblies you should probably install Visual Studio or approp .NET binaries.

Now, let&#39;s encrypt some data.

`acrypto encrypt Merlin! &quot;Hello, Agile Crypto World!&quot;`

You will see output like this:

**I NEED TO REDO THE SCREENSHOTS**

The first set of lines are the JSON metadata for each of the three classes (PBKDF, symmetric cipher and HMAC.) The two lines at the bottom are Base64 ciphertext and HMAC respectively.

Run the same command again.

`acrypto encrypt Merlin! &quot;Hello, Agile Crypto World!&quot;`

Note the ciphertext and HMAC are different, this is because the salt for the PBKDF and the IV for the block cipher are generated by the code automatically each time it&#39;s run. So even in the face of the same password being used, the output is different.

You can see the IV and salt in the output.

Run the command again, but let&#39;s output to a file.

`acrypto encrypt Merlin! &quot;Hello, Agile Crypto World!&quot; \&gt; 1.enc`

To decrypt (and integrity check) the blob, type the following:

`acrypto decrypt Merlin! 1.enc`

and you will see the plaintext.

Now let&#39;s rev this up a little. Open the crypto.config file (note, it&#39;s fragile, so keep a backup copy!) and change this:

`System.Security.Cryptography.Rfc2898DeriveBytes|{&quot;IterationCount&quot;:1000}
System.Security.Cryptography.DESCryptoServiceProvider|{&quot;KeySize&quot;:64,&quot;BlockSize&quot;:64,&quot;FeedbackSize&quot;:8,&quot;Mode&quot;:1,&quot;Padding&quot;:2}
System.Security.Cryptography.HMACSHA1|{&quot;HashName&quot;:&quot;SHA1&quot;,&quot;HashSize&quot;:160}`

To this:

`System.Security.Cryptography.Rfc2898DeriveBytes|{&quot;IterationCount&quot;:25000}
System.Security.Cryptography.AesCryptoServiceProvider|{&quot;KeySize&quot;:128,&quot;BlockSize&quot;:128, ,&quot;Mode&quot;:4,&quot;Padding&quot;:2}
System.Security.Cryptography.HMACSHA512|{&quot;HashName&quot;:&quot;SHA512&quot;,&quot;HashSize&quot;:512}`

We have changed a lot; we changed the cipher (DES -> AES), the PBKDF iteration count (1000 -> 25000), and block mode (ECB (4) -> CBC (1)) and finally, the HMAC (SHA1 -> SHA512.)

Now re-run the tool to encrypt the data **(redirect to 2.enc, not 1.enc)**:

`acrypto encrypt Merlin! &quot;Hello, Agile Crypto World!&quot; \&gt; 2.enc`

If you look at the resulting file, you&#39;ll see that it looks quite different from 1.enc because we changed so much. Note espically that the MAC is huge (SHA512) compared to the previous example (SHA256.)

Finally, the ultimate test – decrypting both blobs with the same code and no code changes needed:

Simply type the following, one after the other and witness the result:

`acrypto decrypt Merlin! 1.enc

acrypto decrypt Merlin! 2.enc`

Voila!

Feedback Welcome!
