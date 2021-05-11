using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace DGC
{


    public static class MrzEncoder
    {
        private static Dictionary<char, string> CHAR_MAPPINGS = new Dictionary<char, string>
        {
            {'\u00E5', "AA" },
            {'\u00C5', "AA"}, // Å
            {'\u00E4', "AE"}, // ä
            {'\u00C4', "AE"}, // Ä
            {'\u00C6', "AE"}, // Æ
            {'\u00E6', "AE"}, // æ    
            {'\u00F6', "OE"}, // ö
            {'\u00D6', "OE"}, // Ö
            {'\u00F8', "OE"}, // ø
            {'\u00D8', "OE"}, // Ø    
            {'\u0132', "IJ"}, // Ĳ
            {'\u0133', "IJ"}, // ĳ
            {'\u00DC', "UE"}, // Ü
            {'\u00FC', "UE"}, // ü
            {'\u00DF', "SS"}, // ß
            {'Þ', "TH"},
            {'Ð', "D"},
            {'Ó', "O"},
            {'Ú', "U"},
            {'Í', "I"},
            {'Ý', "Y"},
            {'Á', "A"},
            {'É', "E"},
        };


        public static string Encode(string input)
        {
            var builder = new StringBuilder(input.Length);
            foreach (var c in input.ToUpper().Trim())
            {
                if (CHAR_MAPPINGS.TryGetValue(c, out string mc))
                {
                    builder.Append(mc);
                }
                else if (c == '’' || c == '\'')
                {
                    // Remove
                }
                else if (Char.IsWhiteSpace(c))
                {
                    builder.Append('<');
                }
                else
                {
                    builder.Append(c);
                }
            }


            // Remove all accents and replace all invalid characters with <
            var normalized = builder.ToString()
                .Normalize();

            var onlyAsci = Regex.Replace(normalized, "[^<[A-Z][0-9]]", "<");
            return onlyAsci;
        }
    }
}
