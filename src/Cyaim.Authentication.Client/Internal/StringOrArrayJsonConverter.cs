using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 兼容 "value" 与 ["a","b"] 两种 JSON 形态的字符串数组转换器（JWT 声明常见差异）。
    /// </summary>
    internal sealed class StringOrArrayJsonConverter : JsonConverter<string[]?>
    {
        public override string[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.Null:
                    return null;
                case JsonTokenType.String:
                    string? single = reader.GetString();
                    return single == null ? Array.Empty<string>() : new[] { single };
                case JsonTokenType.StartArray:
                    var list = new List<string>();
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        if (reader.TokenType == JsonTokenType.String)
                        {
                            string? item = reader.GetString();
                            if (item != null)
                            {
                                list.Add(item);
                            }
                        }
                        else
                        {
                            reader.Skip();
                        }
                    }
                    return list.ToArray();
                default:
                    reader.Skip();
                    return Array.Empty<string>();
            }
        }

        public override void Write(Utf8JsonWriter writer, string[]? value, JsonSerializerOptions options)
        {
            if (value == null)
            {
                writer.WriteNullValue();
                return;
            }

            writer.WriteStartArray();
            foreach (string item in value)
            {
                writer.WriteStringValue(item);
            }
            writer.WriteEndArray();
        }
    }
}
