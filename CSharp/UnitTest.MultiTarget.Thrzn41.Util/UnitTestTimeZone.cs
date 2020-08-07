using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Thrzn41.Util;

namespace UnitTest.MultiTarget.Thrzn41.Util
{
    [TestClass]
    public class UnitTestTimeZone
    {

        [TestMethod]
        public void TestGetWindowsIdFromTzId()
        {
            string id;
            bool   result;

            result = TimeZoneUtils.TryGetWindowsIdFromTzId("Asia/Tokyo", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Tokyo Standard Time", id);

            result = TimeZoneUtils.TryGetWindowsIdFromTzId("America/Los_Angeles", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Pacific Standard Time", id);

            result = TimeZoneUtils.TryGetWindowsIdFromTzId("Etc/GMT+12", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Dateline Standard Time", id);

            result = TimeZoneUtils.TryGetWindowsIdFromTzId("Etc/GMT-14", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Line Islands Standard Time", id);


            result = TimeZoneUtils.TryGetWindowsIdFromTzId("NoExistence/TimeZoneId", out id);
            Assert.IsFalse(result);
            Assert.IsNull(id);


            id = TimeZoneUtils.GetWindowsIdFromTzId("Asia/Tokyo");
            Assert.AreEqual("Tokyo Standard Time", id);

            var ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>(() =>
            {
                id = TimeZoneUtils.GetWindowsIdFromTzId("NoExistence/TimeZoneId");
            });

            Assert.AreEqual("TimeZone id 'NoExistence/TimeZoneId' is not found.", ex.Message);

        }

        [TestMethod]
        public void TestGetTzIdFromWindowsId()
        {
            string id;
            bool result;

            result = TimeZoneUtils.TryGetTzIdFromWindowsId("Tokyo Standard Time", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Asia/Tokyo", id);

            result = TimeZoneUtils.TryGetTzIdFromWindowsId("Pacific Standard Time", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("America/Los_Angeles", id);

            result = TimeZoneUtils.TryGetTzIdFromWindowsId("Dateline Standard Time", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Etc/GMT+12", id);

            result = TimeZoneUtils.TryGetTzIdFromWindowsId("Line Islands Standard Time", out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Pacific/Kiritimati", id);

            result = TimeZoneUtils.TryGetTzIdFromWindowsId("Tokyo Standard Time", out id, TimeZoneUtils.PreferredTzId.TerritoryIndipendent);
            Assert.IsTrue(result);
            Assert.AreEqual("Etc/GMT-9", id);

            result = TimeZoneUtils.TryGetTzIdFromWindowsId("Pacific Standard Time", out id, TimeZoneUtils.PreferredTzId.TerritoryIndipendent);
            Assert.IsTrue(result);
            Assert.AreEqual("PST8PDT", id);

            result = TimeZoneUtils.TryGetTzIdFromWindowsId("GMT Standard Time", out id, TimeZoneUtils.PreferredTzId.TerritoryIndipendent);
            Assert.IsTrue(result);
            Assert.AreEqual("Europe/London", id);


            result = TimeZoneUtils.TryGetTzIdFromWindowsId("No Existence Time Zone Id", out id, TimeZoneUtils.PreferredTzId.TerritoryIndipendent);
            Assert.IsFalse(result);
            Assert.IsNull(id);


            id = TimeZoneUtils.GetTzIdFromWindowsId("Tokyo Standard Time");
            Assert.AreEqual("Asia/Tokyo", id);

            var ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>( () =>
                {
                    id = TimeZoneUtils.GetTzIdFromWindowsId("No Existence Time Zone Id");
                });
    
            Assert.AreEqual("TimeZone id 'No Existence Time Zone Id' is not found.", ex.Message);
        }

        [TestMethod]
        public void TestGetTzIdsFromWindowsId()
        {
            string[] ids;
            bool result;

            result = TimeZoneUtils.TryGetTzIdsFromWindowsId("UTC", out ids);
            Assert.IsTrue(result);

            // it may change in the future.
            Assert.AreEqual(3, ids.Length);
            Assert.IsTrue(ids.Contains("Etc/GMT"));
            Assert.IsTrue(ids.Contains("America/Danmarkshavn"));
            Assert.IsTrue(ids.Contains("Etc/UTC"));


            result = TimeZoneUtils.TryGetTzIdsFromWindowsId("No Existence Time Zone Id", out ids);
            Assert.IsFalse(result);
            Assert.IsNull(ids);


            ids = TimeZoneUtils.GetTzIdsFromWindowsId("UTC");
            Assert.IsNotNull(ids);

            // it may change in the future.
            Assert.AreEqual(3, ids.Length);
            Assert.IsTrue(ids.Contains("Etc/GMT"));
            Assert.IsTrue(ids.Contains("America/Danmarkshavn"));
            Assert.IsTrue(ids.Contains("Etc/UTC"));


            var ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>(() =>
            {
                ids = TimeZoneUtils.GetTzIdsFromWindowsId("No Existence Time Zone Id");
            });

            Assert.AreEqual("TimeZone id 'No Existence Time Zone Id' is not found.", ex.Message);
        }


        [TestMethod]
        public void TestGetTimeZoneInfo()
        {
            TimeZoneInfo timeZoneInfo;
            bool result;
            string id;

            result = TimeZoneUtils.TryGetTimeZoneInfoFromTzId("Asia/Tokyo", out timeZoneInfo);
            Assert.IsTrue(result);
            Assert.IsNotNull(timeZoneInfo);

            result = TimeZoneUtils.TryGetTzIdFromTimeZoneInfo(timeZoneInfo, out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Asia/Tokyo", id);

            result = TimeZoneUtils.TryGetWindowsIdFromTimeZoneInfo(timeZoneInfo, out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Tokyo Standard Time", id);


            result = TimeZoneUtils.TryGetTimeZoneInfoFromWindowsId("Tokyo Standard Time", out timeZoneInfo);
            Assert.IsTrue(result);
            Assert.IsNotNull(timeZoneInfo);

            result = TimeZoneUtils.TryGetTzIdFromTimeZoneInfo(timeZoneInfo, out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Asia/Tokyo", id);



            result = TimeZoneUtils.TryGetTimeZoneInfoFromTzId("NoExistence/TimeZoneId", out timeZoneInfo);
            Assert.IsFalse(result);
            Assert.IsNull(timeZoneInfo);

            result = TimeZoneUtils.TryGetTimeZoneInfoFromWindowsId("No Existence Time Zone Id", out timeZoneInfo);
            Assert.IsFalse(result);
            Assert.IsNull(timeZoneInfo);


            timeZoneInfo = TimeZoneUtils.GetTimeZoneInfoFromTzId("Asia/Tokyo");
            Assert.IsNotNull(timeZoneInfo);

            id = TimeZoneUtils.GetTzIdFromTimeZoneInfo(timeZoneInfo);
            Assert.AreEqual("Asia/Tokyo", id);

            id = TimeZoneUtils.GetWindowsIdFromTimeZoneInfo(timeZoneInfo);
            Assert.AreEqual("Tokyo Standard Time", id);


            var ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>(() =>
            {
                timeZoneInfo = TimeZoneUtils.GetTimeZoneInfoFromTzId("NoExistence/TimeZoneId");
            });

            Assert.AreEqual("TimeZoneInfo for id 'NoExistence/TimeZoneId' is not found.", ex.Message);


            ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>(() =>
            {
                timeZoneInfo = TimeZoneUtils.GetTimeZoneInfoFromWindowsId("No Existence Time Zone Id");
            });

            Assert.AreEqual("TimeZoneInfo for id 'No Existence Time Zone Id' is not found.", ex.Message);


        }

    }
}
