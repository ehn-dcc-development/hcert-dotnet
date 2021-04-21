using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using NL.MinVWS.Encoding;
using System;
using System.IO;

namespace DGC
{
    public class GreenCertificateDecoder
    {
        /// <summary>
        /// Decodes base45 encoded string -> Deflate -> COSE -> CBOR -> arbitrary Json String
        /// </summary>
        /// <param name="base45String">Base45 Encoded string</param>
        /// <returns>Cose object and a digital green card v1 object</returns>
        public CWT Decode(string base45String)
        {
            if (!base45String.StartsWith("HC1:"))
                throw new ArgumentException("Base45 string not valid according to specification");

            base45String = base45String.Substring(4);
            var decodedBytes = Base45Encoding.Decode(base45String);

            var coseBytes = DeflateToCoseBytes(decodedBytes);

            var coseOBj = Sign1CoseMessage.DecodeFromBytes(coseBytes);

            CWT cwt = CWT.DecodeFromBytes(coseOBj);
            
            return cwt;
        }

        private byte[] DeflateToCoseBytes(byte[] decodedBytes)
        {
            if (decodedBytes[0] == 0x78 && decodedBytes[1] == 0xDA)
            {
                var outputStream = new MemoryStream();
                using (var compressedStream = new MemoryStream(decodedBytes))
                using (var inputStream = new InflaterInputStream(compressedStream))
                {
                    inputStream.CopyTo(outputStream);
                    outputStream.Position = 0;
                    return outputStream.ToArray();
                }
            }
            else
            {
                // The data is not compressed
                return decodedBytes;
            }
        }
    }
}


