using System;
using System.IO;
using System.Security.Cryptography;

namespace XfremeUnlocker.Utils
{
    public static class HashCalculator
    {
        public static string CalculateSHA256(string filePath)
        {
            try
            {
                using (var sha = SHA256.Create())
                using (var fs = File.OpenRead(filePath))
                {
                    byte[] hash = sha.ComputeHash(fs);
                    return BitConverter.ToString(hash).Replace("-", "").ToUpper();
                }
            }
            catch
            {
                return null;
            }
        }

        public static string CalculateMD5(string filePath)
        {
            try
            {
                using (var md5 = MD5.Create())
                using (var fs = File.OpenRead(filePath))
                {
                    byte[] hash = md5.ComputeHash(fs);
                    return BitConverter.ToString(hash).Replace("-", "").ToUpper();
                }
            }
            catch
            {
                return null;
            }
        }
    }
}