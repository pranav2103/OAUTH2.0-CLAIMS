//-------------------------------------------------------------------------------------------------
// <copyright file="X509CertificateEncryptionProvider.cs" company="Icertis Inc.">
//     Copyright (c) 2014 Icertis Inc. All Rights Reserved.
// </copyright>
//
// <summary>
//     Implements encryption and decryption methods for protecting configuration settings in Azure environment.
// </summary>
//-------------------------------------------------------------------------------------------------

namespace okta.Models
{
    using System.Data;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography.Xml;
    using System.Text;
    using System.Xml;
    using System.Xml.Linq;



    /// <summary>
    /// Class implements encryption and decryption methods for protecting configuration settings in Azure environment.
    /// </summary>
    /// <remarks>
    /// This is required, because default provider in System.Configuration will not support looking up certificate based on thumbprint. 
    /// Whereas in Azure, certificate has to be looked up by thumbprint from Azure certificate store.
    /// </remarks>
    public class X509CertificateEncryptionProvider
    {
       
        /// <summary>
        /// Cipher data key separator.
        /// </summary>
        private const char CipherDataDelimter = '$';

        /// <summary>
        /// Cipher data element.
        /// </summary>
        private const string CipherDataElement = "CipherData";

        /// <summary>
        /// Encrypted key element.
        /// </summary>
        private const string EncryptedKeyElement = "EncryptedKey";

        /// <summary>
        /// Place holder data envelop node.
        /// </summary>
        private const string DataEnvelopTemplate = "<Data>{0}</Data>";

        /// <summary>
        /// Crypto provider key type.
        /// </summary>
        private const string CryptoProviderKeyType = "rsaKey";

        /// <summary>
        /// Thumbprint of the certificate used for encryption and decryption.
        /// </summary>
        private string thumbprint;

        /// <summary>
        /// Initializes a new instance of the X509CertificateEncryptionProvider class.
        /// </summary>
        /// <param name="certificateThumbprint">Certificate thumb print.</param>
        public X509CertificateEncryptionProvider(string certificateThumbprint)
        {
            this.thumbprint = certificateThumbprint;
            
        }

        /// <summary>
        /// Gets the service certificate used by the configuration protector.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2 ServiceCertificate
        {
            get
            {
                return this.GetCertificate(this.thumbprint);
            }
        }

        /// <summary>
        /// Get the certificate from a specific store/location/subject.
        /// </summary>
        /// <param name="name">Store name</param>
        /// <param name="location">Store location</param>
        /// <param name="thumbPrint">Thumbprint name</param>
        /// <returns>
        /// Certificate object.
        /// </returns>
        public static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, string thumbPrint)
        {
            X509Store store = new X509Store(name, location);
            X509Certificate2Collection certificates = null;
            store.Open(OpenFlags.ReadOnly);

            try
            {
                X509Certificate2 result = null;

                // Every time we call store.Certificates property, a new collection will be returned.
                certificates = store.Certificates;
                for (int i = 0; i < certificates.Count; i++)
                {
                    X509Certificate2 cert = certificates[i];

                    if (cert.Thumbprint != null && cert.Thumbprint.ToUpperInvariant() == thumbPrint.ToUpperInvariant())
                    {
                        if (result != null)
                        {
                            throw new DataException(string.Format(CultureInfo.InvariantCulture, "More than one certificate was found for thumbprint {0}", thumbPrint));
                        }

                        result = new X509Certificate2(cert);
                    }
                }

                if (result == null)
                {
                    throw new DataException(string.Format(CultureInfo.InvariantCulture, "No certificate was found for thumbprint Name {0}", thumbPrint));
                }

                return result;
            }
            finally
            {
                if (certificates != null)
                {
                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];
                        cert.Reset();
                    }
                }

                store.Close();
            }
        }

        /// <summary>
        /// Decrypts the XML node passed to it.
        /// </summary>
        /// <param name="encryptedData">
        /// The data to decrypt.
        /// </param>
        /// <param name="ceritifateThumbprint">
        /// The certificate Thumbprint.
        /// </param>
        /// <returns>
        /// Decrypted data.
        /// </returns>
        public string Decrypt(string encryptedData, string ceritifateThumbprint)
        {
            if (string.IsNullOrWhiteSpace(ceritifateThumbprint))
            {
                throw new DataException("Certificate thumbprint should not be empty.");
            }

            this.thumbprint = ceritifateThumbprint;
            StringBuilder builder = new StringBuilder();
            builder.Append("<EncryptedData ");
            builder.Append("Type=\"http://www.w3.org/2001/04/xmlenc#Element\" ");
            builder.Append("xmlns=\"http://www.w3.org/2001/04/xmlenc#\">");
            builder.Append($"<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\" />");
            builder.Append("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
            builder.Append("<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">");
            builder.Append("<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\" />");
            builder.Append("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
            builder.Append("<KeyName>rsaKey</KeyName>");
            builder.Append("</KeyInfo>");
            builder.Append("<CipherData><CipherValue>{0}</CipherValue></CipherData>");
            builder.Append("</EncryptedKey>");
            builder.Append("</KeyInfo>");
            builder.Append("<CipherData><CipherValue>{1}</CipherValue></CipherData>");
            builder.Append("</EncryptedData>");

            // Base64 string do not have $ sign, it is okay to use this as delimiter
            string[] data = encryptedData.Split(CipherDataDelimter);

            if (!this.IsBase64EncodedString(data[0]) || !this.IsBase64EncodedString(data[1]))
            {
                throw new DataException("The encrypted data is not correctly formatted");
            }

            string encryptedEnvelop = string.Format(CultureInfo.InvariantCulture, builder.ToString(), data[0], data[1]);
            return this.DecryptCore(encryptedEnvelop);
        }

        /// <summary>
        /// Encrypts the XML node passed to it. 
        /// </summary>
        /// <param name="dataToEncrypt">
        /// The data encrypted.
        /// </param>
        /// <param name="certificateThumbprint">
        /// The certificate Thumbprint.
        /// </param>
        /// <returns>
        /// Encrypted data.
        /// </returns>
        public string Encrypt(string dataToEncrypt, string certificateThumbprint)
        {
            if (string.IsNullOrWhiteSpace(certificateThumbprint))
            {
                throw new DataException(string.Format(CultureInfo.InvariantCulture, "Certificate thumbprint should not be empty - {0}", certificateThumbprint));
            }

            this.thumbprint = certificateThumbprint;
            string encryptedData = this.EncryptCore(dataToEncrypt);

            XmlReader reader = XmlReader.Create(new StringReader(encryptedData));
            XElement document = XElement.Load(reader, LoadOptions.None);

            XNamespace keyNamespace = "http://www.w3.org/2001/04/xmlenc#";
            string keyCipherValue = document.Descendants(keyNamespace + EncryptedKeyElement)
                                            .Descendants(keyNamespace + CipherDataElement)
                                            .ElementAt(0)
                                            .Value;

            XNamespace rootNamespace = "http://www.w3.org/2001/04/xmlenc#";
            string dataCipherValue =
                document.Descendants(rootNamespace + CipherDataElement).ElementAt(1).Value;

            // Base64 string do not have $ sign, it is okay to use this as delimiter
            return string.Format(CultureInfo.InvariantCulture, "{0}${1}", keyCipherValue, dataCipherValue);
        }

        /// <summary>
        /// Decrypts the XML node passed to it.
        /// </summary>
        /// <param name="encryptedData">The data to decrypt.</param>
        /// <returns>Decrypted data.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security.Xml", "CA3057:DoNotUseLoadXml", Justification = "LoadXml is ok here")]
        internal string DecryptCore(string encryptedData)
        {
            var document = new XmlDocument();

            // Get the RSA private key.  This key will decrypt
            // a symmetric key that was embedded in the XML document.
            var cryptoServiceProvider = this.GetCryptoServiceProvider(false);
            document.PreserveWhitespace = true;
            document.XmlResolver = null;
            document.LoadXml(string.Format(CultureInfo.InvariantCulture, DataEnvelopTemplate, encryptedData));
            var xml = new EncryptedXml(document);

            // Add a key-name mapping.This method can only decrypt documents
            // that present the specified key name.
            xml.AddKeyNameMapping(CryptoProviderKeyType, cryptoServiceProvider);
            xml.DecryptDocument();
            cryptoServiceProvider.Clear();
            if (document.DocumentElement != null)
            {
                return document.DocumentElement.InnerXml;
            }

            return string.Empty;
        }

        /// <summary>
        /// Encrypts the XML node. 
        /// </summary>
        /// <param name="dataToEncrypt">The data encrypted.</param>
        /// <returns>Encrypted data.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security.Cryptography", "CA5357:RijndaelCannotBeUsed", Justification = "Its ok here"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security.Xml", "CA3057:DoNotUseLoadXml", Justification = "LoadXml is ok here")]
        private string EncryptCore(string dataToEncrypt)
        {
            // Get the RSA public key to encrypt the node. This key will encrypt
            // a symmetric key, which will then be encryped in the XML document.
            var cryptoServiceProvider = this.GetCryptoServiceProvider(true);

            // Create an XML document and load the node to be encrypted in it. 
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.XmlResolver = null;
            XmlReaderSettings xmlReaderSettings = new XmlReaderSettings { XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit };
            document.Load(XmlReader.Create(new StringReader(string.Format(CultureInfo.InvariantCulture, DataEnvelopTemplate, dataToEncrypt)), xmlReaderSettings));

            // Create a new instance of the EncryptedXml class
            // and use it to encrypt the XmlElement with the
            // a new random symmetric key.
            EncryptedXml xml = new EncryptedXml(document);
            XmlElement documentElement = document.DocumentElement;
            SymmetricAlgorithm symmetricAlgorithm = new RijndaelManaged();

            // Create a 192 bit random key.
            byte[] data = new byte[0x18];
            new RNGCryptoServiceProvider().GetBytes(data);
            symmetricAlgorithm.Key = data;
           
            symmetricAlgorithm.GenerateIV();
            symmetricAlgorithm.Padding = PaddingMode.PKCS7;

            byte[] buffer = xml.EncryptData(documentElement, symmetricAlgorithm, true);

            // Construct an EncryptedData object and populate
            // it with the encryption information.
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.Type = EncryptedXml.XmlEncElementUrl;

            // Create an EncryptionMethod element so that the
            // receiver knows which algorithm to use for decryption.
            encryptedData.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#aes192-cbc");
            encryptedData.KeyInfo = new KeyInfo();

            // Encrypt the session key and add it to an EncryptedKey element.
            EncryptedKey encryptedKey = new EncryptedKey();
            encryptedKey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
            encryptedKey.KeyInfo = new KeyInfo();
            encryptedKey.CipherData = new CipherData();
            encryptedKey.CipherData.CipherValue = EncryptedXml.EncryptKey(symmetricAlgorithm.Key, cryptoServiceProvider, false);
            KeyInfoName clause = new KeyInfoName();
            clause.Value = CryptoProviderKeyType;

            // Add the encrypted key to the EncryptedData object.
            encryptedKey.KeyInfo.AddClause(clause);
            KeyInfoEncryptedKey key2 = new KeyInfoEncryptedKey(encryptedKey);
            encryptedData.KeyInfo.AddClause(key2);
            encryptedData.CipherData = new CipherData();
            encryptedData.CipherData.CipherValue = buffer;

            // Replace the element from the original XmlDocument
            // object with the EncryptedData element.
            EncryptedXml.ReplaceElement(documentElement, encryptedData, true);
            foreach (XmlNode node2 in document.ChildNodes)
            {
                if (node2.NodeType == XmlNodeType.Element)
                {
                    foreach (XmlNode node3 in node2.ChildNodes)
                    {
                        if (node3.NodeType == XmlNodeType.Element)
                        {
                            return node3.OuterXml;
                        }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Get either the public key for encrypting configuration sections or the private key to decrypt them. 
        /// </summary>
        /// <param name="encryption">Indicate whether the encryption is on.</param>
        /// <returns>Crypto service provider of type <see cref="RSACryptoServiceProvider"/>.</returns>
        private RSA GetCryptoServiceProvider(bool encryption)
        {
            var cert = this.GetCertificate(this.thumbprint);
            return encryption
                ? (RSA)cert.PublicKey.Key
                : (RSA)cert.PrivateKey;
        }

        /// <summary>
        /// Get certificate from the Local Machine store, based on the given thumbprint.
        /// </summary>
        /// <param name="thumbPrint">Thumbprint of the certificate used for encryption and decryption.</param>
        /// <returns>Certificate of type <see cref="X509Certificate2"/>.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Justification = "Non static method is ok here")]
        private X509Certificate2 GetCertificate(string thumbPrint)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            X509Certificate2Collection certificates = null;
            store.Open(OpenFlags.ReadOnly);

            try
            {
                X509Certificate2 result = null;

                certificates = store.Certificates;

                for (int i = 0; i < certificates.Count; i++)
                {
                    X509Certificate2 cert = certificates[i];

                    if (cert.Thumbprint.ToUpperInvariant() == thumbPrint.ToUpperInvariant())
                    {
                        result = new X509Certificate2(cert);

                        return result;
                    }
                }

                if (result == null)
                {
                    X509Store userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    userStore.Open(OpenFlags.ReadOnly);
                    certificates = userStore.Certificates;

                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];

                        if (cert.Thumbprint.ToUpperInvariant() == thumbPrint.ToUpperInvariant())
                        {
                            result = new X509Certificate2(cert);

                            return result;
                        }
                    }

                    if (result == null)
                    {
                        throw new DataException(string.Format(CultureInfo.InvariantCulture, "No certificate was found for thumbprint {0}", thumbPrint));
                    }
                }

                return null;
            }
            finally
            {
                if (certificates != null)
                {
                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];
                        cert.Reset();
                    }
                }

                store.Close();
            }
        }

        /// <summary>
        /// Determines whether the specified input is a valid BASE64 encoded string.
        /// </summary>
        /// <param name="input">The input to check for BASE64 encoded nature</param>
        /// <returns>True if the specified input is a valid BASE64 encoded string, otherwise false</returns>
        private bool IsBase64EncodedString(string input)
        {
            try
            {
                System.Convert.FromBase64String(input);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
