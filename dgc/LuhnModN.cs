using System.Linq;

namespace DGC
{
    public static class LuhnModN
    {
        public static char GenerateCheckCharacter(string input)
        {
            const string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/:";
            int factor = 2;
            int sum = 0;
            int n = charset.Length;

            foreach (var inputChar in input.Reverse())
            {
                int codePoint = charset.IndexOf(inputChar);
                if (codePoint == -1) continue;
                int addend = factor * codePoint;

                factor = (factor == 2) ? 1 : 2;

                addend = (addend / n) + (addend % n);
                sum += addend;
            }

            int remainder = sum % n;
            int checkCodePoint = (n - remainder) % n;

            return charset[checkCodePoint];
        }
    }
}
