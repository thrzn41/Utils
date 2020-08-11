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
            bool result;

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

            var ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>(() =>
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
        public void TestGetTimeZoneInfoAndGetIdFromTimeZoneInfo()
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



            timeZoneInfo = TimeZoneInfo.CreateCustomTimeZone("Asia/Tokyo", TimeSpan.FromHours(9.0f), "Tokyo", "Tokyo");

            result = TimeZoneUtils.TryGetTzIdFromTimeZoneInfo(timeZoneInfo, out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Asia/Tokyo", id);

            result = TimeZoneUtils.TryGetWindowsIdFromTimeZoneInfo(timeZoneInfo, out id);
            Assert.IsTrue(result);
            Assert.AreEqual("Tokyo Standard Time", id);


            timeZoneInfo = TimeZoneInfo.CreateCustomTimeZone("NoExistenceTimeZone", TimeSpan.FromHours(1.0f), "No Existence", "No Existence");

            result = TimeZoneUtils.TryGetTzIdFromTimeZoneInfo(timeZoneInfo, out id);
            Assert.IsFalse(result);
            Assert.IsNull(id);

            result = TimeZoneUtils.TryGetWindowsIdFromTimeZoneInfo(timeZoneInfo, out id);
            Assert.IsFalse(result);
            Assert.IsNull(id);


            ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>(() =>
            {
                id = TimeZoneUtils.GetTzIdFromTimeZoneInfo(timeZoneInfo);
            });

            Assert.AreEqual("TimeZone id 'NoExistenceTimeZone' is not found.", ex.Message);

            ex = Assert.ThrowsException<TimeZoneInfoNotFoundException>(() =>
            {
                id = TimeZoneUtils.GetWindowsIdFromTimeZoneInfo(timeZoneInfo);
            });

            Assert.AreEqual("TimeZone id 'NoExistenceTimeZone' is not found.", ex.Message);

        }


        private const string DATE_TIME_FORMATE = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffK";

        [TestMethod]
        public void TestGetDateTimeOffset()
        {
            DateTime dateTime;
            DateTimeOffset dateTimeOffset;
            DateTimeOffset dateTimeOffsetResult;
            TimeZoneInfo timeZoneInfo;

            timeZoneInfo = TimeZoneUtils.GetTimeZoneInfoFromTzId("Asia/Tokyo");

            dateTime = new DateTime(2021, 01, 01, 00, 00, 00);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-01-01T00:00:00.000+09:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 01, 01, 00, 00, 00, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-01-01T09:00:00.000+09:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTimeOffset = new DateTimeOffset(2021, 01, 01, 00, 00, 00, TimeSpan.FromHours(9.0f));
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-01-01T00:00:00.000+09:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTimeOffset = new DateTimeOffset(2021, 01, 01, 00, 00, 00, TimeSpan.Zero);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-01-01T09:00:00.000+09:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTimeOffset = new DateTimeOffset(2021, 01, 01, 00, 00, 00, TimeSpan.FromHours(1.0f));
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-01-01T08:00:00.000+09:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));




            timeZoneInfo = TimeZoneInfo.Utc;

            dateTime = new DateTime(2021, 01, 01, 00, 00, 00);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-01-01T00:00:00.000+00:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 01, 01, 00, 00, 00, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-01-01T00:00:00.000+00:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));





            timeZoneInfo = TimeZoneUtils.GetTimeZoneInfoFromTzId("America/Los_Angeles");

            dateTime = new DateTime(2021, 01, 01, 00, 00, 00);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-01-01T00:00:00.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 03, 14, 01, 59, 59);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-03-14T01:59:59.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 03, 14, 03, 00, 00);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-03-14T03:00:00.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTime = new DateTime(2021, 03, 14, 09, 59, 59, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-03-14T01:59:59.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 03, 14, 10, 00, 00, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-03-14T03:00:00.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTimeOffset = new DateTimeOffset(2021, 03, 14, 09, 59, 59, TimeSpan.Zero);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-03-14T01:59:59.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTimeOffset = new DateTimeOffset(2021, 03, 14, 10, 00, 00, TimeSpan.Zero);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-03-14T03:00:00.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTimeOffset = new DateTimeOffset(2021, 03, 14, 01, 59, 59, TimeSpan.FromHours(-8.0f));
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-03-14T01:59:59.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTimeOffset = new DateTimeOffset(2021, 03, 14, 03, 00, 00, TimeSpan.FromHours(-7.0f));
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-03-14T03:00:00.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTime = new DateTime(2021, 11, 07, 00, 59, 59);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-11-07T00:59:59.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 11, 07, 01, 59, 59);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:59:59.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 11, 07, 02, 00, 00);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-11-07T02:00:00.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTime = new DateTime(2021, 11, 07, 07, 59, 59, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-11-07T00:59:59.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 11, 07, 08, 00, 00, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:00:00.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 11, 07, 08, 59, 59, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:59:59.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTime = new DateTime(2021, 11, 07, 09, 00, 00, DateTimeKind.Utc);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTime, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:00:00.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTimeOffset = new DateTimeOffset(2021, 11, 07, 08, 59, 59, TimeSpan.Zero);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:59:59.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTimeOffset = new DateTimeOffset(2021, 11, 07, 09, 00, 00, TimeSpan.Zero);
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:00:00.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));


            dateTimeOffset = new DateTimeOffset(2021, 11, 07, 01, 59, 59, TimeSpan.FromHours(-7.0f));
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:59:59.000-07:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));

            dateTimeOffset = new DateTimeOffset(2021, 11, 07, 01, 00, 00, TimeSpan.FromHours(-8.0f));
            dateTimeOffsetResult = TimeZoneUtils.GetDateTimeOffset(dateTimeOffset, timeZoneInfo);
            Assert.AreEqual("2021-11-07T01:00:00.000-08:00", dateTimeOffsetResult.ToString(DATE_TIME_FORMATE));
        }

    }
}
