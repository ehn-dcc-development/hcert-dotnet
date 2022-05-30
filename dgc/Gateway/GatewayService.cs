using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

        public async Task<string> UploadRevocationBatch(GatewayRevocationBatch batch)
        {
            string batchjson = JsonConvert.SerializeObject(batch);

            var content = new StringContent(batchjson, Encoding.UTF8, "application/json");

            var response = await HttpClient.PostAsync("/revocation-list", content);

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<GatewayRevocationBatchList> GetRevocationBatches(DateTime? lastModifiedDate = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/revocation-list");

            var lastModifiedDatestr = (lastModifiedDate ?? new DateTime(2021, 6, 1,0,0,0)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK");
            request.Headers.TryAddWithoutValidation("If-Modified-Since", lastModifiedDatestr); // "2021-06-01T00:00:00Z");

            var response = await HttpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var result = JsonConvert.DeserializeObject<GatewayRevocationBatchList>(content);
            return result;
        }

        public async Task<(GatewayRevocationBatch, SignedCms)> GetRevocationBatch(string batchId)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"/revocation-list/{batchId}");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/cms"));

            var response = await HttpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var cms64b = Convert.FromBase64String(content);
            var signedCms = new SignedCms();
            signedCms.Decode(cms64b);
            var json = Encoding.UTF8.GetString(signedCms.ContentInfo.Content);

            var result = JsonConvert.DeserializeObject<GatewayRevocationBatch>(json);
            return (result, signedCms);
        }

        public async Task<string> UploadNewRevokationBatch(GatewayRevocationBatch batch, X509Certificate2 uploadCertificate)
        {
            var jsoncontent = JsonConvert.SerializeObject(batch);
            var jsonbytes = Encoding.UTF8.GetBytes(jsoncontent);
            var contentInfo = new ContentInfo(jsonbytes);
            var cms = new SignedCms(contentInfo);

            var signer = new CmsSigner(uploadCertificate);
            cms.ComputeSignature(signer);

            var content = Convert.ToBase64String(cms.Encode());

            var request = new HttpRequestMessage(HttpMethod.Post, $"/revocation-list");
            request.Content = new StringContent(content, Encoding.UTF8, "application/cms");

            var response = await HttpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            // BatchId
            return response.Headers.GetValues("ETag").FirstOrDefault();
        }

        public async Task<bool> DeleteRevokationBatch(string batchId, X509Certificate2 uploadCertificate)
        {
            var jsoncontent = JsonConvert.SerializeObject(new { batchId = batchId });
            var jsonbytes = Encoding.UTF8.GetBytes(jsoncontent);
            var contentInfo = new ContentInfo(jsonbytes);
            var cms = new SignedCms(contentInfo);

            var signer = new CmsSigner(uploadCertificate);
            cms.ComputeSignature(signer);

            var content = Convert.ToBase64String(cms.Encode());

            var request = new HttpRequestMessage(HttpMethod.Delete, $"/revocation-list");
            request.Content = new StringContent(content, Encoding.UTF8, "application/cms");

            var response = await HttpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode && response.StatusCode == System.Net.HttpStatusCode.NotFound) return false;
            
            response.EnsureSuccessStatusCode();
            return true;
        }
    }
}
