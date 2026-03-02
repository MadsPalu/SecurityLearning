using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using PasswordCrackerCentralized.model;
using PasswordCrackerCentralized.util;

namespace PasswordCrackerCentralized
{
    public class Cracking
    {
        private readonly int _workerCount;
        private readonly bool _verbose;

        public Cracking(int? workerCount = null, bool verbose = false)
        {
            _workerCount = workerCount ?? Environment.ProcessorCount;
            _verbose = verbose;
        }

        /// <summary>
        /// Runs the password cracking algorithm
        /// </summary>
        public void RunCracking()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            List<UserInfo> userInfos = PasswordFileHandler.ReadPasswordFile("passwords.txt");
            Console.WriteLine("passwd opened");

            Dictionary<string, List<UserInfo>> usersByHash = BuildUsersByHash(userInfos);
            ConcurrentDictionary<string, UserInfoClearText> crackedUsers =
                new ConcurrentDictionary<string, UserInfoClearText>(StringComparer.Ordinal);

            IEnumerable<string> dictionaryEntries = File.ReadLines("webster-dictionary.txt");
            ParallelOptions parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = _workerCount
            };

            // Master/worker setup: master feeds dictionary entries, workers test all word variations.
            Parallel.ForEach(
                dictionaryEntries,
                parallelOptions,
                () => (HashAlgorithm) new SHA1CryptoServiceProvider(),
                (dictionaryEntry, loopState, index, messageDigest) =>
                {
                    CheckWordWithVariations(dictionaryEntry, usersByHash, crackedUsers, messageDigest);
                    return messageDigest;
                },
                messageDigest => messageDigest.Dispose());

            List<UserInfoClearText> result = crackedUsers.Values
                .OrderBy(entry => entry.Username)
                .ToList();

            stopwatch.Stop();
            Console.WriteLine(string.Join(", ", result));
            Console.WriteLine("Out of {0} password {1} was found ", userInfos.Count, result.Count);
            Console.WriteLine();
            Console.WriteLine("Workers used: {0}", _workerCount);
            Console.WriteLine("Time elapsed: {0}", stopwatch.Elapsed);
        }

        private static Dictionary<string, List<UserInfo>> BuildUsersByHash(IEnumerable<UserInfo> userInfos)
        {
            Dictionary<string, List<UserInfo>> usersByHash = new Dictionary<string, List<UserInfo>>(StringComparer.Ordinal);

            foreach (UserInfo userInfo in userInfos)
            {
                string hashKey = Convert.ToBase64String(userInfo.EntryptedPassword.ToArray());

                if (!usersByHash.TryGetValue(hashKey, out List<UserInfo> usersWithSameHash))
                {
                    usersWithSameHash = new List<UserInfo>();
                    usersByHash[hashKey] = usersWithSameHash;
                }

                usersWithSameHash.Add(userInfo);
            }

            return usersByHash;
        }

        /// <summary>
        /// Generates a lot of variations, encrypts each and compares to all entries in the password file
        /// </summary>
        private void CheckWordWithVariations(
            string dictionaryEntry,
            IReadOnlyDictionary<string, List<UserInfo>> usersByHash,
            ConcurrentDictionary<string, UserInfoClearText> crackedUsers,
            HashAlgorithm messageDigest)
        {
            CheckSingleWord(usersByHash, crackedUsers, dictionaryEntry, messageDigest);
            CheckSingleWord(usersByHash, crackedUsers, dictionaryEntry.ToUpper(), messageDigest);
            CheckSingleWord(usersByHash, crackedUsers, StringUtilities.Capitalize(dictionaryEntry), messageDigest);
            CheckSingleWord(usersByHash, crackedUsers, StringUtilities.Reverse(dictionaryEntry), messageDigest);

            for (int i = 0; i < 100; i++)
            {
                CheckSingleWord(usersByHash, crackedUsers, dictionaryEntry + i, messageDigest);
            }

            for (int i = 0; i < 100; i++)
            {
                CheckSingleWord(usersByHash, crackedUsers, i + dictionaryEntry, messageDigest);
            }

            for (int i = 0; i < 10; i++)
            {
                for (int j = 0; j < 10; j++)
                {
                    CheckSingleWord(usersByHash, crackedUsers, i + dictionaryEntry + j, messageDigest);
                }
            }
        }

        /// <summary>
        /// Checks a single candidate by hashing it once and doing O(1) lookup in the encrypted-password index
        /// </summary>
        private void CheckSingleWord(
            IReadOnlyDictionary<string, List<UserInfo>> usersByHash,
            ConcurrentDictionary<string, UserInfoClearText> crackedUsers,
            string possiblePassword,
            HashAlgorithm messageDigest)
        {
            char[] charArray = possiblePassword.ToCharArray();
            byte[] passwordAsBytes = Array.ConvertAll(charArray, PasswordFileHandler.GetConverter());
            byte[] encryptedPassword = messageDigest.ComputeHash(passwordAsBytes);
            string encryptedPasswordKey = Convert.ToBase64String(encryptedPassword);

            if (!usersByHash.TryGetValue(encryptedPasswordKey, out List<UserInfo> matches))
            {
                return;
            }

            foreach (UserInfo userInfo in matches)
            {
                if (crackedUsers.TryAdd(userInfo.Username, new UserInfoClearText(userInfo.Username, possiblePassword)) && _verbose)
                {
                    Console.WriteLine(userInfo.Username + " " + possiblePassword);
                }
            }
        }
    }
}
