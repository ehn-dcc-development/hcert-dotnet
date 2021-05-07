namespace DGC
{
    using System;
    using System.Collections.Generic;

    using System.Globalization;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// EU Digital Green Certificate
    /// </summary>
    public partial class DgCertificate
    {
        /// <summary>
        /// Date of Birth of the person addressed in the DGC. ISO 8601 date format restricted to
        /// range 1900-2099
        /// </summary>
        [JsonProperty("dob")]
        [JsonConverter(typeof(CustomDateTimeConverter))]
        public DateTime DateOfBirth { get; set; }

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
        /// The family or primary name(s) of the person addressed in the certificate
        /// </summary>
        [JsonProperty("fn", NullValueHandling = NullValueHandling.Ignore)]
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string FamilyName { get; set; }

        /// <summary>
        /// The family name(s) of the person transliterated
        /// </summary>
        [JsonProperty("fnt")]
        //[JsonConverter(typeof(FluffyMinMaxLengthCheckConverter))]
        public string FamilyNameTransliterated { get; set; }

        /// <summary>
        /// The given name(s) of the person addressed in the certificate
        /// </summary>
        [JsonProperty("gn", NullValueHandling = NullValueHandling.Ignore)]
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string GivenName { get; set; }

        /// <summary>
        /// The given name(s) of the person transliterated
        /// </summary>
        [JsonProperty("gnt", NullValueHandling = NullValueHandling.Ignore)]
        //[JsonConverter(typeof(FluffyMinMaxLengthCheckConverter))]
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
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string CertificateIdentifier { get; set; }

        /// <summary>
        /// Country of Test
        /// </summary>
        [JsonProperty("co")]
        public string CountryOfTest { get; set; }

        /// <summary>
        /// ISO 8601 Date: Certificate Valid From
        /// </summary>
        [JsonProperty("df")]
        public DateTimeOffset ValidFrom { get; set; }

        /// <summary>
        /// Certificate Valid Until
        /// </summary>
        [JsonProperty("du")]
        public DateTimeOffset ValitUntil { get; set; }

        /// <summary>
        /// ISO 8601 Date of First Positive Test Result
        /// </summary>
        [JsonProperty("fr")]
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
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string CertificateIdentifier { get; set; }

        /// <summary>
        /// Country of Test
        /// </summary>
        [JsonProperty("co")]
        public string CountryOfTest { get; set; }

        /// <summary>
        /// Date/Time of Test Result
        /// </summary>
        [JsonProperty("dr", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset? TestResutDate { get; set; }

        /// <summary>
        /// Certificate Issuer
        /// </summary>
        [JsonProperty("is")]
        //[JsonConverter(typeof(PurpleMinMaxLengthCheckConverter))]
        public string Issuer { get; set; }

        /// <summary>
        /// RAT Test name and manufacturer
        /// </summary>
        [JsonProperty("ma", NullValueHandling = NullValueHandling.Ignore)]
        public string TestNameAndManufacturer { get; set; }

        /// <summary>
        /// NAA Test Name
        /// </summary>
        [JsonProperty("nm", NullValueHandling = NullValueHandling.Ignore)]
        public string TestName { get; set; }

        /// <summary>
        /// Date/Time of Sample Collection
        /// </summary>
        [JsonProperty("sc")]
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
}