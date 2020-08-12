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
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Thrzn41.Util;

namespace Tool.TimeZoneMap
{
    class Program
    {

        private const string PROJECT_NAME = "Tool.TimeZoneMap";

        private const string TIME_ZONE_UTILS_PROJECT_NAME = "MultiTarget.Thrzn41.Util";

        private const string TIME_ZONE_UTILS_CS = "TimeZoneUtils.cs";

        private const string TIME_ZONE_UTILS_RESOURCES_PATH = "Resources";


        private const string RF_WINDOWS_ID_TO_TZ_ID_MAP = "WindowsIdToTzId.dat";
        private const string RF_TZ_ID_TO_WINDOWS_ID_MAP = "TzIdToWindowsId.dat";

        private const string RF_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP = "WindowsIdToTzIdTerritoryIndipendent.dat";

        private const string SRC_NAME_SPACE = "namespace Tool.TimeZoneMap.Thrzn41.Util";
        private const string DEST_NAME_SPACE = "namespace Thrzn41.Util";

        private const string UNNECESSARY_USING = "using Thrzn41.Util;";

        private const string PH_WINDOWS_ID_TO_TZ_ID_MAP = "// $WINDOWS_ID_TO_TZ_ID_MAP$";
        private const string PH_TZ_ID_TO_WINDOWS_ID_MAP = "// $TZ_ID_TO_WINDOWS_ID_MAP$";

        private const string PH_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP = "// $WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP$";

        private const string PH_TIME_ZONE_ID_MAX = "/* $TIME_ZONE_ID_MAX$ */";

        private const string PH_WINDOWS_ID_TO_TZ_ID_MAP_SIZE = "/* $WINDOWS_ID_TO_TZ_ID_MAP_SIZE$ */";
        private const string PH_TZ_ID_TO_WINDOWS_ID_MAP_SIZE = "/* $TZ_ID_TO_WINDOWS_ID_MAP_SIZE$ */";

        private const string PH_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP_SIZE = "/* $WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP_SIZE$ */";

        private const string PH_WINDOWS_ID_VERSION_TAG = "$WINDOWS_ID_VERSION_TAG$";
        private const string PH_TZ_ID_VERSION_TAG      = "$TZ_ID_VERSION_TAG$";


        private static readonly Uri WINDOWS_ZONE_INFO = new Uri("https://raw.githubusercontent.com/unicode-org/cldr/master/common/supplemental/windowsZones.xml");

        private static readonly FileInfo EXE_PATH = new FileInfo(Assembly.GetExecutingAssembly().Location);

        private DirectoryInfo projectDir;

        private ZoneMapInfo windowsIdToTzIdMap = new ZoneMapInfo();
        private ZoneMapInfo tzIdToWindowsIdMap = new ZoneMapInfo();

        private ZoneMapInfo windowsIdToTzIdTerritoryIndipendentMap = new ZoneMapInfo();

        private HashSet<string> timeZoneIds = new HashSet<string>();


        private Program()
        {
            this.projectDir = searchDir(EXE_PATH.Directory, PROJECT_NAME);
        }

        private void writeMapInfo(ZoneMapInfo mapInfo, string indent, StreamWriter writer, string resourceFile)
        {
            string pattern = String.Format("{0}{{{{ {{0, -{1}}} {{1, -{2}}} }}}},", indent, mapInfo.SrcMax + 3, mapInfo.DestMax + 2);


            using (var resfw = new FileStream(String.Format("{0}{1}{2}{1}{3}{1}{4}", this.projectDir.Parent.FullName, Path.DirectorySeparatorChar, TIME_ZONE_UTILS_PROJECT_NAME, TIME_ZONE_UTILS_RESOURCES_PATH, resourceFile), FileMode.Create, FileAccess.Write, FileShare.Read))
            using (var reswriter = new StreamWriter(resfw, UTF8Utils.UTF8_WITHOUT_BOM))
            {

                reswriter.NewLine = "\n";

                foreach (var item in mapInfo.Map)
                {
                    writer.WriteLine(
                        pattern,
                        String.Format("\"{0}\",", item.Key),
                        String.Format("\"{0}\"",  item.Value)
                    );

                    reswriter.WriteLine("{0},{1}", item.Key, item.Value);
                }
            }
        }

        private void generateTimeZoneUtils(MapTimeZone mapTimeZone)
        {
            using (var fsr    = new FileStream(String.Format("{0}{1}{2}", this.projectDir.FullName, Path.DirectorySeparatorChar, TIME_ZONE_UTILS_CS), FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var reader = new StreamReader(fsr, true))
            using (var fsw    = new FileStream(String.Format("{0}{1}{2}{1}{3}", this.projectDir.Parent.FullName, Path.DirectorySeparatorChar, TIME_ZONE_UTILS_PROJECT_NAME, TIME_ZONE_UTILS_CS), FileMode.Create, FileAccess.Write, FileShare.Read))
            using (var writer = new StreamWriter(fsw, UTF8Utils.UTF8_WITH_BOM))
            {
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();

                    if(line.Contains(SRC_NAME_SPACE))
                    {
                        line = line.Replace(SRC_NAME_SPACE, DEST_NAME_SPACE);
                    }
                    if (line.Contains(PH_TIME_ZONE_ID_MAX))
                    {
                        line = line.Replace(PH_TIME_ZONE_ID_MAX, this.timeZoneIds.Count.ToString());
                    }
                    if(line.Contains(PH_WINDOWS_ID_TO_TZ_ID_MAP_SIZE))
                    {
                        line = line.Replace(PH_WINDOWS_ID_TO_TZ_ID_MAP_SIZE, this.windowsIdToTzIdMap.Map.Count.ToString());
                    }
                    if (line.Contains(PH_TZ_ID_TO_WINDOWS_ID_MAP_SIZE))
                    {
                        line = line.Replace(PH_TZ_ID_TO_WINDOWS_ID_MAP_SIZE, this.tzIdToWindowsIdMap.Map.Count.ToString());
                    }
                    if (line.Contains(PH_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP_SIZE))
                    {
                        line = line.Replace(PH_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP_SIZE, this.windowsIdToTzIdTerritoryIndipendentMap.Map.Count.ToString());
                    }
                    if (line.Contains(PH_WINDOWS_ID_VERSION_TAG))
                    {
                        line = line.Replace(PH_WINDOWS_ID_VERSION_TAG, mapTimeZone.OtherVersion);
                    }
                    if (line.Contains(PH_TZ_ID_VERSION_TAG))
                    {
                        line = line.Replace(PH_TZ_ID_VERSION_TAG, mapTimeZone.TypeVersion);
                    }


                    if (line.Contains(PH_WINDOWS_ID_TO_TZ_ID_MAP))
                    {
                        writeMapInfo(this.windowsIdToTzIdMap, line.Replace(PH_WINDOWS_ID_TO_TZ_ID_MAP, ""), writer, RF_WINDOWS_ID_TO_TZ_ID_MAP);
                    }
                    else if (line.Contains(PH_TZ_ID_TO_WINDOWS_ID_MAP))
                    {
                        writeMapInfo(this.tzIdToWindowsIdMap, line.Replace(PH_TZ_ID_TO_WINDOWS_ID_MAP, ""), writer, RF_TZ_ID_TO_WINDOWS_ID_MAP);

                    }
                    else if (line.Contains(PH_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP))
                    {
                        writeMapInfo(this.windowsIdToTzIdTerritoryIndipendentMap, line.Replace(PH_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP, ""), writer, RF_WINDOWS_ID_TO_TZ_ID_TERRITORY_INDIPENDENT_MAP);
                    }
                    else if(line != UNNECESSARY_USING)
                    {
                        writer.WriteLine(line);
                    }
                }
            }

        }

        private void addToMap(List<MapZone> mapInfo, MapZone item)
        {
            string[] ianaNames = item.TzId.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var name in ianaNames)
            {
                string windowsId = item.WindowsId.Trim();
                string tzId      = name.Trim();

                if(String.IsNullOrWhiteSpace(windowsId) || String.IsNullOrWhiteSpace(tzId) || windowsId.Contains(",") || tzId.Contains(","))
                {
                    // Current export dataformat does not expect ",".
                    // If we find such data, may need to review data format to be exported.
                    throw (new InvalidOperationException("Unexpected data was found. Need to check source data or review export format."));
                }

                this.timeZoneIds.Add(windowsId);
                this.timeZoneIds.Add(tzId);

                mapInfo.Add(
                        new MapZone { WindowsId = windowsId, TzId = tzId, Territory = item.Territory }
                    );
            }

        }

        private void buildMapInfo(MapZone[] baseMap)
        {
            var mapInfo = new List<MapZone>();

            foreach (var item in baseMap)
            {
                if(item.Territory == "001")
                {
                    addToMap(mapInfo, item);
                }
            }

            foreach (var item in baseMap)
            {
                if (item.Territory != "001")
                {
                    addToMap(mapInfo, item);
                }
            }


            foreach (var item in mapInfo)
            {
                this.windowsIdToTzIdMap.Add(item.WindowsId, item.TzId);
                this.tzIdToWindowsIdMap.Add(item.TzId,    item.WindowsId);

                if (item.Territory == "ZZ" && !item.WindowsId.StartsWith("UTC"))
                {
                    this.windowsIdToTzIdTerritoryIndipendentMap.Add(item.WindowsId, item.TzId);
                }
            }

        }


        private DirectoryInfo searchDir(DirectoryInfo baseDir, string directoryName)
        {
            if(baseDir == null)
            {
                return null;
            }

            if(baseDir.Name == directoryName)
            {
                return baseDir;
            }
            else
            {
                return searchDir(baseDir.Parent, directoryName);
            }
        }

        private void backupSourceFile(string text)
        {
            using (var fs     = new FileStream(String.Format("{0}{1}Data{1}windowsZones.xml", this.projectDir.FullName, Path.DirectorySeparatorChar), FileMode.Create, FileAccess.Write, FileShare.Read))
            using (var writer = new StreamWriter(fs, UTF8Utils.UTF8_WITHOUT_BOM))
            {
                writer.Write(text);
            }
        }

        private async Task generateAsync()
        {
            string text;

            using (var httpClient = new HttpClient())
            {
                using (var response = await httpClient.GetAsync(WINDOWS_ZONE_INFO, HttpCompletionOption.ResponseHeadersRead))
                {
                    response.EnsureSuccessStatusCode();

                    using (var content = response.Content)
                    {
                        text = await content.ReadAsStringAsync();
                    }
                }
            }

            backupSourceFile(text);

            var serializer = new XmlSerializer(typeof(WindowsZone));

            WindowsZone zoneMap;

            using (var reader = new StringReader(text))
            {
                zoneMap = serializer.Deserialize(reader) as WindowsZone;
            }


            buildMapInfo(zoneMap.MapTimeZones[0].MapZones);


            generateTimeZoneUtils(zoneMap.MapTimeZones[0]);
        }

        static async Task Main(string[] args)
        {
            try
            {
                var app = new Program();

                await app.generateAsync();

                Console.WriteLine("Thrzn41.Util.TimeZoneUtils exported!");
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
            }
            finally
            {
                Console.WriteLine("Press any key to exit.");
                Console.ReadKey(true);
            }
        }
    }
}
