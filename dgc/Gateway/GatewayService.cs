using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DCC.Gateway
{
    public class GatewayService
    {
        public GatewayService(string baseAddress, X509Certificate2 certificate)
        {
            _baseAddress = baseAddress;
            _certificate = certificate;
        }

        private string _baseAddress;
        private readonly X509Certificate2 _certificate;
        private object _lock = new object();

        private HttpClient _httpClient;
        private HttpClient HttpClient
        {
            get
            {
                if (_httpClient == null)
                {
                    lock (_lock)
                    {
                        if (_httpClient == null)
                        {
                            var address = new Uri(_baseAddress);

                            var handler = new HttpClientHandler();
                            if (_certificate != null)
                            {
                                handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                                handler.SslProtocols = SslProtocols.Tls12;
                                handler.ClientCertificates.Add(_certificate);
                            }
                            var client = new HttpClient(handler);
                            client.BaseAddress = address;

                            client.DefaultRequestHeaders.Accept.Clear();
                            client.DefaultRequestHeaders.Accept.Add(
                                new MediaTypeWithQualityHeaderValue("application/json"));

                            _httpClient = client;
                        }
                    }
                }
                return _httpClient;
            }
        }

        public async Task<GatewayDSCResponse[]> GetAllDscFromGateway()
        {
            const string trusListDsc = "/trustList/DSC";
            var response = await HttpClient.GetAsync(trusListDsc);

            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var result = JsonConvert.DeserializeObject<GatewayDSCResponse[]>(content);

            return result;
        }

        public async Task<IReadOnlyList<string>> GetValuesets()
        {
            const string valuesseturl = "/valuesets";
            var response = await HttpClient.GetAsync(valuesseturl);

            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();

            var valueset = new List<string>();
            using (var reader = new JsonTextReader(new System.IO.StringReader(content)))
            {
                foreach (var a in (JArray)JToken.ReadFrom(reader))
                {
                    valueset.Add(a.Value<string>());
                }
            }
            return valueset;
        }

        public async Task<Dictionary<string, GatewayValueset>> GetValueset(string valuesetId)
        {
            string valuesseturl = "/valuesets/" + valuesetId;
            var response = await HttpClient.GetAsync(valuesseturl);

            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();

            var valueset = new Dictionary<string, GatewayValueset>();
            using (var reader = new JsonTextReader(new System.IO.StringReader(content)))
            {
                var root = (JObject)JToken.ReadFrom(reader);

                foreach (var item in (root["valueSetValues"]))
                {
                    var value = ((JProperty)item).Name;
                    var set = new GatewayValueset
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
}
