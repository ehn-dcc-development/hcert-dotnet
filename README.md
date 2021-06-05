# dgc-dotnet
C# /.NET implementation of the [Electronic Health Certificate Specification](https://github.com/ehn-digital-green-development/ehn-dgc-schema) to create and decode Digital Covid Certificates

## About
This is a dotnet standard library.

## How to use
###Verifing a certificate
```c#
// First connect to the DCC Gateway
// Get the TLS certificate 
// From a certificate store or this could also be a file or some other methods
X509Certificate2 cert = new X509Certificate2([ByteArrayOfTheCert])

var gatewayService = new GatewayService("https://url to the gateway", cert);

var dscs = gatewayService.GetAllDscFromGateway();

// ISecretariatService needs to be implemented
var secratariatService = new MyImpSecratariatService(dscs);

// Decode the barcode to cwt object
GreenCertificateDecoder decoder = new GreenCertificateDecoder();
var cwt = decoder.Decode(barcodeContent);

// Verify
GreenCertificateVerifier verifier = new GreenCertificateVerifier(secratariatService);
var (isvalid, reason) = await verifier.Verify(cwt);
```

###Issuing certificate

```c#
// Get the signing certificate with a private key
// From a certificate store (HSM) or this could also be a file or some other methods
X509Certificate2 cert = new X509Certificate2([ByteArrayOfTheCert])

// Create CWT
var ci = "URN:UVCI:01:IS:SomeUniqeID";

CWT cwt = new CWT();
cwt.DGCv1 = new DgCertificate
{
    Name = new Nam
    {
        FamilyName = lastName,
        GivenName = firstName,
        FamilyNameTransliterated = MrzEncoder.Encode(lastName),
        GivenNameTraslitaerated = MrzEncoder.Encode(firstName),
    },
    Version = "1.0.0",
    DateOfBirth = dateofbirth,
    Test = new TestEntry[]
    {
        new TestEntry
        {
            CertificateIdentifier = ci + "#" + LuhnModN.GenerateCheckCharacter(ci),
            CountryOfTest = "IS",
            Disease = "840539006",
            Issuer="Directorate of Health of Iceland",
            SampleTakenDate = sampletakenDate,
            TestingCenter = "Department of ClinicalMicrobiology,Landspitali",
            TestNameAndManufacturer = "1278",
            TestName = "Xiamen Boson Biotech Co. Ltd, Rapid SARS-CoV-2 Antigen Test Card",
            TestResult = "260415000",
            TestResutDate = testresultDate,
            TestType = "LP6464-4"
        }
    }
};
cwt.ExpiarationTime = testDate.AddHours(72);
cwt.IssueAt = DateTime.Now;
cwt.Issuer = "IS";

string encodedDigitalCovidCert = new GreenCertificateEncoder(cert).Encode(cwt);

// Create a QR Code
using var stream = QrCodeGenerator.GenerateQR(dcc);
using var filestream = File.Create("qrCode.png");
stream.CopyTo(filestream);
```

##Outstanding issues
Verifying extended key parameters and the signing country has not been implented
Signature certificates when downloaded are not verified agains CA

