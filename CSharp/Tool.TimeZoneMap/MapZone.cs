/* 
 * MIT License
 * 
 * Copyright(c) 2020 thrzn41
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml.Serialization;

namespace Tool.TimeZoneMap
{
    public class MapZone
    {
        [XmlAttribute(AttributeName = "other")]
        public string WindowsId { get; set; }

        [XmlAttribute(AttributeName = "territory")]
        public string Territory { get; set; }

        [XmlAttribute(AttributeName = "type")]
        public string TzId { get; set; }

    }

    public class MapTimeZone
    {
        [XmlAttribute(AttributeName = "otherVersion")]
        public string OtherVersion { get; set; }

        [XmlAttribute(AttributeName = "typeVersion")]
        public string TypeVersion { get; set; }

        [XmlElement(ElementName = "mapZone")]
        public MapZone[] MapZones { get; set; }
    }

    public class Version
    {
        [XmlAttribute(AttributeName = "number")]
        public string Number { get; set; }
    }

    [XmlRoot(ElementName = "supplementalData")]
    public class WindowsZone
    {
        [XmlElement(ElementName = "version")]
        public Version Version { get; set; }

        [XmlArray(ElementName = "windowsZones")]
        [XmlArrayItem(ElementName = "mapTimezones")]
        public MapTimeZone[] MapTimeZones { get; set; }
    }
}
