using System;
using System.Threading;

namespace XfremeUnlocker.UI
{
    public class ProgressBar
    {
        private readonly int total;
        private int current;
        private readonly string prefix;

        public ProgressBar(int total, string prefix = "")
        {
            this.total = Math.Max(1, total);
            this.current = 0;
            this.prefix = prefix;
        }

        public void Update(int increment = 1)
        {
            current = Math.Min(total, current + increment);
            Draw();
        }

        private void Draw()
        {
            int percent = (int)(100.0 * current / total);
            int width = 30;
            int filled = (int)(width * current / (double)total);
            string bar = new string('█', filled) + new string('░', width - filled);

            Console.Write($"\r{prefix} |{bar}| {percent}% [{current}/{total}]");
        }

        public void Finish()
        {
            current = total;
            Draw();
            Console.WriteLine();
        }

        public static void Smooth(string message, double duration = 0.6)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[*] {message}");
            Console.ResetColor();

            int steps = 15;
            for (int i = 0; i <= steps; i++)
            {
                int percent = (int)(100.0 * i / steps);
                string bar = new string('█', i * 2) + new string('░', 30 - i * 2);
                Console.Write($"\r    |{bar}| {percent}%");
                Thread.Sleep((int)(duration * 1000 / steps));
            }
            Console.WriteLine();
        }
    }
}