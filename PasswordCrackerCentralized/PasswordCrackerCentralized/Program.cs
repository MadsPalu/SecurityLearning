namespace PasswordCrackerCentralized
{
    class Program
    {
        static void Main(string[] args)
        {
            int? workers = null;
            if (args.Length > 0 && int.TryParse(args[0], out int parsedWorkers) && parsedWorkers > 0)
            {
                workers = parsedWorkers;
            }

            bool verbose = args.Length > 1 && args[1].ToLowerInvariant() == "verbose";

            Cracking cracker = new Cracking(workers, verbose);
            cracker.RunCracking();
        }
    }
}
