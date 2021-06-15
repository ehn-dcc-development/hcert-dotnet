using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace DGC
{
    /// <summary>
    /// Digital Green Certificate Date Time Converter
    /// </summary>
    public class DGCDateTimeConverter : IsoDateTimeConverter
    {
        private readonly IEnumerable<(string pattern, string format)> formatters;

        /// <summary>
        /// Initialize converter with default values
        /// </summary>
        public DGCDateTimeConverter()
        {
            formatters = new (string pattern, string formatter)[]
            {
                // Formates 'sc' and 'dr' in 't' array as ISO 8601 Date
                // If pattern matches JSON Path, formatter is used
                (@"t\[\d+\]\.(sc|dr)", "yyyy'-'MM'-'dd'T'HH':'mm':'ss.FFFFFFFK")
            };

            this.DateTimeFormat = "yyyy-MM-dd";
            this.Culture = CultureInfo.InvariantCulture;
        }

        /// <summary>
        /// Initialize converter with custom formatters
        /// </summary>
        /// <param name="_formatters">Collection of Custom formatters</param>
        public DGCDateTimeConverter(IEnumerable<(string pattern, string format)> _formatters)
            : this()
        {
            formatters = _formatters;
        }

        /// <summary>
        /// Serializes Dates with given format
        /// </summary>
        /// <param name="writer">Writes value as string</param>
        /// <param name="value">Date to be serialized</param>
        /// <param name="serializer">Serializer settings</param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            string text = null;

            try
            {
                if (value is DateTime dateTime)
                {
                    if (formatters == null || formatters.Count() == 0)
                    {
                        text = dateTime
                            .ToUniversalTime()
                            .ToString(DateTimeFormat, Culture);
                    }
                    else
                    {
                        foreach (var formatter in formatters)
                        {
                            Regex tester = new Regex(formatter.pattern);

                            if (tester.IsMatch(writer.Path))
                            {
                                text = dateTime
                                    .ToUniversalTime()
                                    .ToString(formatter.format, Culture);
                            }
                        }

                        if (text == null)
                        {
                            text = dateTime
                                    .ToUniversalTime()
                                    .ToString(DateTimeFormat, Culture);
                        }
                    }
                }
                else if (value is DateTimeOffset dateTimeOffset)
                {
                    if (formatters == null || formatters.Count() == 0)
                    {
                        text = dateTimeOffset
                            .ToUniversalTime()
                            .ToString(DateTimeFormat, Culture);
                    }
                    else
                    {
                        foreach (var formatter in formatters)
                        {
                            Regex tester = new Regex(formatter.pattern);

                            if (tester.IsMatch(writer.Path))
                            {
                                text = dateTimeOffset
                                    .ToUniversalTime()
                                    .ToString(formatter.format, Culture);
                            }
                        }

                        if (text == null)
                        {
                            text = dateTimeOffset
                                    .ToUniversalTime()
                                    .ToString(DateTimeFormat, Culture);
                        }
                    }
                }
                else
                {
                    throw new ArgumentException();
                }

                writer.WriteValue(text);
            }
            catch (Exception)
            {
                base.WriteJson(writer, value, serializer);
            }
        }
    }
}
