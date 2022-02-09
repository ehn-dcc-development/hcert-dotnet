using SkiaSharp;
using System;
using System.Drawing;
using System.IO;
using ZXing;
using ZXing.QrCode.Internal;

namespace DCC
{
    public static class QrCodeGenerator
    {
        /// <summary>
        /// Generates 2D code containing DGC
        /// </summary>
        /// <param name="text">DGC to be encoded</param>
        [Obsolete("This method will only work on Windows in .net6, GenerateQR2 is cross-platform")]
        public static Stream GenerateQR(string prefixDgc)
        {
            var qrCodeWriter = new BarcodeWriterPixelData
            {
                Format = BarcodeFormat.QR_CODE,
                Options = new ZXing.QrCode.QrCodeEncodingOptions
                {
                    Height = 400,
                    Width = 400,

                    // 25% error correction
                    ErrorCorrection = ErrorCorrectionLevel.Q
                }
            };

            var pixelData = qrCodeWriter.Write(prefixDgc);
            // creating a bitmap from the raw pixel data; if only black and white colors are used it makes no difference    
            // that the pixel data ist BGRA oriented and the bitmap is initialized with RGB    
            using (var bitmap = new Bitmap(pixelData.Width, pixelData.Height, System.Drawing.Imaging.PixelFormat.Format32bppRgb))
                
            {
                var bitmapData = bitmap.LockBits(new Rectangle(0, 0, pixelData.Width, pixelData.Height), System.Drawing.Imaging.ImageLockMode.WriteOnly, System.Drawing.Imaging.PixelFormat.Format32bppRgb);
                try
                {
                    // we assume that the row stride of the bitmap is aligned to 4 byte multiplied by the width of the image    
                    System.Runtime.InteropServices.Marshal.Copy(pixelData.Pixels, 0, bitmapData.Scan0, pixelData.Pixels.Length);
                }
                finally
                {
                    bitmap.UnlockBits(bitmapData);
                }

                var ms = new MemoryStream();
                // save to stream as PNG    
                bitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Png);

                return ms;
            }
        }

        /// <summary>
        /// Generates 2D code containing DGC, cross-platform
        /// </summary>
        /// <param name="prefixDgc"></param>
        /// <returns></returns>
        public static Stream GenerateQR2(string prefixDgc)
        {
            var qrCodeWriter = new BarcodeWriterPixelData
            {
                Format = BarcodeFormat.QR_CODE,
                Options = new ZXing.QrCode.QrCodeEncodingOptions
                {
                    Height = 400,
                    Width = 400,
                    // 25% error correction
                    ErrorCorrection = ErrorCorrectionLevel.Q
                }
            };

            var bitMatrix = qrCodeWriter.Encode(prefixDgc);

            using (SKBitmap ss = new SKBitmap(400, 400))
            {
                for (int x = 0; x < bitMatrix.Width; x++)
                {
                    for (int y = 0; y < bitMatrix.Height; y++)
                    {
                        ss.SetPixel(x, y, bitMatrix[x, y] ? SKColors.Black : SKColors.White );
                    }
                }
                var data = ss.Encode(SKEncodedImageFormat.Png, 100);
                return data.AsStream();
            }
        }


    }
}
