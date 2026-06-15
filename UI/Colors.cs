using System;

namespace XfremeUnlocker.UI
{
    /// <summary>
    /// Цветовая схема консоли
    /// </summary>
    public static class C
    {
        public static void Red(string text) { Console.ForegroundColor = ConsoleColor.Red; Console.Write(text); Console.ResetColor(); }
        public static void Green(string text) { Console.ForegroundColor = ConsoleColor.Green; Console.Write(text); Console.ResetColor(); }
        public static void Yellow(string text) { Console.ForegroundColor = ConsoleColor.Yellow; Console.Write(text); Console.ResetColor(); }
        public static void Cyan(string text) { Console.ForegroundColor = ConsoleColor.Cyan; Console.Write(text); Console.ResetColor(); }
        public static void Blue(string text) { Console.ForegroundColor = ConsoleColor.Blue; Console.Write(text); Console.ResetColor(); }
        public static void Magenta(string text) { Console.ForegroundColor = ConsoleColor.Magenta; Console.Write(text); Console.ResetColor(); }
        public static void DarkGray(string text) { Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write(text); Console.ResetColor(); }
        public static void White(string text) { Console.ForegroundColor = ConsoleColor.White; Console.Write(text); Console.ResetColor(); }

        public static void RedLine(string text) { Red(text + "\n"); }
        public static void GreenLine(string text) { Green(text + "\n"); }
        public static void YellowLine(string text) { Yellow(text + "\n"); }
        public static void CyanLine(string text) { Cyan(text + "\n"); }
        public static void BlueLine(string text) { Blue(text + "\n"); }
        public static void DarkGrayLine(string text) { DarkGray(text + "\n"); }
        public static void WhiteLine(string text) { White(text + "\n"); }
    }
}