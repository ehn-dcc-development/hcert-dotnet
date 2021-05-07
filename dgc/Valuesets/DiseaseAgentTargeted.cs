using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;

namespace dgc.Valuesets
{
    public static class Valuessets
    {
        public static Dictionary<string, Valueset> DiseaseAgentTargeted { get; } = ParseJsonValueset(Path.Combine("Valuesets", "disease-agent-targeted.json"));
        public static Dictionary<string, Valueset> TestManf { get; } = ParseJsonValueset(Path.Combine("Valuesets", "test-manf.json"));
        public static Dictionary<string, Valueset> TestResult { get; } = ParseJsonValueset(Path.Combine("Valuesets", "test-result.json"));
        public static Dictionary<string, Valueset> VaccineMahManf { get; } = ParseJsonValueset(Path.Combine("Valuesets", "vaccine-mah-manf.json"));
        public static Dictionary<string, Valueset> VaccineMedicinalProdoct { get; } = ParseJsonValueset(Path.Combine("Valuesets", "vaccine-medicinal-product.json"));
        public static Dictionary<string, Valueset> VaccineProphylaxis { get; } = ParseJsonValueset(Path.Combine("Valuesets", "vaccine-prophylaxis.json"));

        public static Dictionary<string, Valueset> ParseJsonValueset(string filename)
        {
            var valueset = new Dictionary<string, Valueset>();
            using (var file = File.OpenText(filename))
            using (var reader = new JsonTextReader(file))
            {
                var root = (JObject)JToken.ReadFrom(reader);

                foreach (var item in (root["valueSetValues"]))
                {
                    var value = ((Newtonsoft.Json.Linq.JProperty)item).Name;
                    var set = new Valueset
                    {
                        Value = value,
                        Display = item.First["display"].ToString(),
                        Lang = item.First["lang"].ToString(),
                        Active = item.First["active"].ToObject<bool>(),
                        Version = item.First["version"].ToString(),
                        System = item.First["system"].ToString(),
                        SetDate = DateTime.Parse(root["valueSetDate"].ToString()),
                        SetId = root["valueSetId"].ToString()
                    };

                    valueset.Add(value, set);
                }
            }
            return valueset;
        }
    }


    public class Valueset
    {
        public string Value { get; set; }
        public string SetId { get; set; }
        public DateTime SetDate { get; set; }
        public string Display { get; set; }
        public string Lang { get; set; }
        public bool Active { get; set; }
        public string Version { get; set; }
        public string System { get; set; }

        public override string ToString()
        {
            return Display;
        }
    }
}
