using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace DCC
{
    /// <summary>
    /// EU Digital Green Certificate v.1.3.0
    /// </summary>
    public partial class DgCertificate
    {
        /// <summary>
        /// Date of birth of the DCC holder.  
        /// Complete or partial date without time restricted to the range from 1900-01-01 to 2099-12-31.  
        /// Exactly 1 (one) non-empty field MUST be provided if the complete or partial date of birth is known.If the date of birth is not known even partially, the field MUST be set to an empty string "". This should match the information as provided on travel documents.
        /// One of the following ISO 8601 formats MUST be used if information on date of birth is available.Other options are not supported.
        /// YYYY-MM-DD
        /// YYYY-MM
        /// YYYY
        /// </summary>
        [JsonProperty("dob")]
        public string DateOfBirthString { get; set; }

        [JsonIgnore]
        public DateTime? DateOfBirth 
        { 
            get 
            {
                if (DateTime.TryParse(DateOfBirthString, out var res))
                {
                    return res;
                } 
                else if (int.TryParse(DateOfBirthString, out int year))
                {
                    return new DateTime(year, 1, 1);
                }
                return null;
            }
            set
            {
                DateOfBirthString = value?.ToString("yyyy-MM-dd") ?? "";
            } 
        }

        /// <summary>
        /// Surname(s), given name(s) - in that order
        /// </summary>
        [JsonProperty("nam")]
        public Nam Name { get; set; }

        /// <summary>
        /// Recovery Group
        /// </summary>
        [JsonProperty("r", NullValueHandling = NullValueHandling.Ignore)]
        public RecoveryElement[] Recovery { get; set; }

        /// <summary>
        /// Test Group
        /// </summary>
        [JsonProperty("t", NullValueHandling = NullValueHandling.Ignore)]
        public TestEntry[] Test { get; set; }

        /// <summary>
        /// Vaccination Group
        /// </summary>
        [JsonProperty("v", NullValueHandling = NullValueHandling.Ignore)]
        public VaccinationEntry[] Vaccination { get; set; }

        /// <summary>
        /// Version of the schema, according to Semantic versioning (ISO, https://semver.org/ version
        /// 2.0.0 or newer)
        /// </summary>
        [JsonProperty("ver")]
        public string Version { get; set; }
    }

    /// <summary>
    /// Surname(s), given name(s) - in that order
    ///
    /// Person name: Surname(s), given name(s) - in that order
    /// </summary>
    public partial class Nam
    {
        /// <summary>
        /// The surename or primary name(s) of the person addressed in the certificate
        /// </summary>
        [JsonProperty("fn", NullValueHandling = NullValueHandling.Ignore)]
        public string SurnameName { get; set; }

        /// <summary>
        /// The family name(s) of the person transliterated
        /// </summary>
        [JsonProperty("fnt")]
        public string SurameTransliterated { get; set; }

        /// <summary>
        /// The given name(s) of the person addressed in the certificate
        /// </summary>
        [JsonProperty("gn", NullValueHandling = NullValueHandling.Ignore)]
        public string GivenName { get; set; }

        /// <summary>
        /// The given name(s) of the person transliterated
        /// </summary>
        [JsonProperty("gnt", NullValueHandling = NullValueHandling.Ignore)]
        public string GivenNameTraslitaerated { get; set; }
    }

    /// <summary>
    /// Recovery Entry
    /// </summary>
    public partial class RecoveryElement
    {
        /// <summary>
        /// Unique Certificate Identifier, UVCI
        /// </summary>
        [JsonProperty("ci")]
        public string CertificateIdentifier { get; set; }

        /// <summary>
        /// Country of Test
        /// </summary>
        [JsonProperty("co")]
        public string CountryOfTest { get; set; }

        /// <summary>
        /// The first date on which the certificate is considered to be valid. The date MUST NOT be earlier than the date calculated as r/fr + 11 days. 
        /// The date MUST be provided in the format YYYY-MM-DD(complete date without time). Other formats are not supported.
        /// </summary>
        [JsonProperty("df")]
        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTimeOffset ValidFrom { get; set; }

        /// <summary>
        /// The last date on which the certificate is considered to be valid, assigned by the certificate issuer. The date MUST NOT be after the date calculated as r/fr + 180 days. 
        /// </summary>
        [JsonProperty("du")]
        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTimeOffset ValidUntil { get; set; }

        /// <summary>
        /// The date when a sample for the NAAT test producing a positive result was collected, in the format YYYY-MM-DD (complete date without time). Other formats are not supported. 
        /// </summary>
        [JsonProperty("fr")]
        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTimeOffset FirstPositiveTestResult { get; set; }

        /// <summary>
        /// Certificate Issuer
        /// </summary>
        [JsonProperty("is")]
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string Issuer { get; set; }

        [JsonProperty("tg")]
        public string Disease { get; set; }
    }

    /// <summary>
    /// Test Entry
    /// </summary>
    public partial class TestEntry
    {
        /// <summary>
        /// Unique Certificate Identifier, UVCI
        /// </summary>
        [JsonProperty("ci")]
        public string CertificateIdentifier { get; set; }

        /// <summary>
        /// Country of Test
        /// </summary>
        [JsonProperty("co")]
        public string CountryOfTest { get; set; }

        /// <summary>
        /// Certificate Issuer
        /// </summary>
        [JsonProperty("is")]
        public string Issuer { get; set; }

        /// <summary>
        /// Rapid antigen test (RAT) device identifier from the JRC database
        /// </summary>
        [JsonProperty("ma", NullValueHandling = NullValueHandling.Ignore)]
        public string RATTestDeviceIdentifier { get; set; }

        /// <summary>
        /// The name of the nucleic acid amplification test (NAAT) used. The name should include the name of the test manufacturer and the commercial name of the test, separated by a comma. 
        /// The field is optional.When supplied, it MUST NOT be empty.The field SHOULD only be used for NAAT tests. It SHOULD NOT be used for RAT tests, as their name is supplied indirectly through the test device identifier (t/ma). 
        /// </summary>
        [JsonProperty("nm", NullValueHandling = NullValueHandling.Ignore)]
        public string NAATTestName { get; set; }

        /// <summary>
        /// Date/Time of Sample Collection
        /// </summary>
        [JsonProperty("sc")]
        [JsonConverter(typeof(NoMillisDateTimeConverter))]
        public DateTimeOffset SampleTakenDate { get; set; }

        /// <summary>
        /// Testing Centre
        /// </summary>
        [JsonProperty("tc")]
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string TestingCenter { get; set; }

        [JsonProperty("tg")]
        public string Disease { get; set; }

        /// <summary>
        /// Test Result
        /// </summary>
        [JsonProperty("tr")]
        public string TestResult { get; set; }

        /// <summary>
        /// Type of Test
        /// </summary>
        [JsonProperty("tt")]
        public string TestType { get; set; }
    }

    /// <summary>
    /// Vaccination Entry
    /// </summary>
    public partial class VaccinationEntry
    {
        /// <summary>
        /// Unique Certificate Identifier: UVCI
        /// </summary>
        [JsonProperty("ci")]
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string CertificateIdentifier { get; set; }

        /// <summary>
        /// Country of Vaccination
        /// </summary>
        [JsonProperty("co")]
        public string CountryOfVaccination { get; set; }

        /// <summary>
        /// Dose Number
        /// </summary>
        [JsonProperty("dn")]
        public long DoseNumber { get; set; }

        /// <summary>
        /// Date of Vaccination
        /// </summary>
        [JsonProperty("dt")]
        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTimeOffset VaccinationDate { get; set; }

        /// <summary>
        /// Certificate Issuer
        /// </summary>
        [JsonProperty("is")]
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string Issuer { get; set; }

        /// <summary>
        /// Marketing Authorization Holder - if no MAH present, then manufacturer
        /// </summary>
        [JsonProperty("ma")]
        public string Manufacturer { get; set; }

        /// <summary>
        /// vaccine medicinal product
        /// </summary>
        [JsonProperty("mp")]
        public string MedicalProduct { get; set; }

        /// <summary>
        /// Total Series of Doses
        /// </summary>
        [JsonProperty("sd")]
        public long TotalDoses { get; set; }

        /// <summary>
        /// disease or agent targeted
        /// </summary>
        [JsonProperty("tg")]
        public string Disease { get; set; }

        /// <summary>
        /// vaccine or prophylaxis
        /// </summary>
        [JsonProperty("vp")]
        public string Vaccine { get; set; }
    }
    
    class CustomDateTimeConverter : IsoDateTimeConverter
    {
        public CustomDateTimeConverter()
        {
            DateTimeFormat = "yyyy-MM-dd";
        }
    }

    public class NoMillisDateTimeConverter : IsoDateTimeConverter
    {
        public NoMillisDateTimeConverter()
        {
            DateTimeFormat = "yyyy-MM-ddTHH:mm:ssZ";
        }
    }
}