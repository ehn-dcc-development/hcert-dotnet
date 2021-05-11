﻿using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace dgc.Gateway
{
    public class GatewayService
    {
        public GatewayService(string baseAddress, string certificatePfxPath, string certificatePassword)
        {
            _baseAddress = baseAddress;
            _certificatePath = certificatePfxPath;
            _certificatePassword = certificatePassword;
        }

        private string _baseAddress;
        private string _certificatePath;
        private string _certificatePassword;

        private HttpClient _httpClient;
        private HttpClient HttpClient
        {
            get
            {
                if (_httpClient != null) return _httpClient;
                var address = new Uri(_baseAddress);

                var handler = new HttpClientHandler();
                if (!string.IsNullOrEmpty(_certificatePath))
                {
                    handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                    handler.SslProtocols = SslProtocols.Tls12;
                    var file = System.IO.File.ReadAllBytes(_certificatePath);
                    handler.ClientCertificates.Add(new X509Certificate2(file, _certificatePassword));
                }
                var client = new HttpClient(handler);
                client.BaseAddress = address;

                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(
                    new MediaTypeWithQualityHeaderValue("application/json"));

                _httpClient = client;
                return _httpClient;
            }
        }

        public async Task<GatewayDSCResponse[]> GetAllDscFromGateway()
        {
            const string trusListDsc = "/trustList/DSC";
            var response = await HttpClient.GetAsync(trusListDsc);

            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var result = Newtonsoft.Json.JsonConvert.DeserializeObject<GatewayDSCResponse[]>(content);

            return result;
        }

        public class GatewayDSCResponse
        {
            public string kid { get; set; }
            public DateTime timestamp { get; set; }
            public string country { get; set; }
            public string certificateType { get; set; }
            public string thumbprint { get; set; }
            public string signature { get; set; }
            public string rawData { get; set; }
        }
    }
}