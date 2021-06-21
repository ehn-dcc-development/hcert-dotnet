using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using NL.MinVWS.Encoding;
using System;
using System.IO;

namespace DCC
{
    public class GreenCertificateDecoder
    {
        /// <summary>
        /// Decodes base45 encoded string -> Inflate -> COSE -> CBOR -> arbitrary Json String
        /// </summary>
        /// <param name="base45String">Base45 Encoded string</param>
        /// <returns>Cose object and a digital green card v1 object</returns>
        public CWT Decode(string base45String)
        {
            if (!base45String.StartsWith("HC1:"))
                throw new ArgumentException("Base45 string not valid according to specification");

            base45String = base45String.Substring(4);
            var decodedBytes = Base45Encoding.Decode(base45String);

            var coseBytes = InflateToCoseBytes(decodedBytes);

            var coseOBj = Sign1CoseMessage.DecodeFromBytes(coseBytes);

            CWT cwt = CWT.DecodeFromBytes(coseOBj);

            return cwt;
        }

        private byte[] InflateToCoseBytes(byte[] decodedBytes)
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
    }
}


