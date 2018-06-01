using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Specialized;
using System.Linq;
using Thrzn41.Util;

namespace UnitTest.DotNetCore.Thrzn41.Util
{
    [TestClass]
    public class UnitTestBasic
    {

        [TestMethod]
        public void TestLocalProtectedString()
        {
            using (var ps1 = LocalProtectedString.FromString("Hello"))
            {
                var ps2 = LocalProtectedString.FromString("Hello");

                Assert.AreEqual(128, ps1.Entropy.Length);
                Assert.AreEqual(128, ps2.Entropy.Length);

                Assert.AreEqual(false, ps1.EncryptedData.SequenceEqual(ps2.EncryptedData));

                Assert.AreEqual("Hello", ps1.DecryptToString());
                Assert.AreEqual("Hello", ps2.DecryptToString());


                var ps3 = LocalProtectedString.FromEncryptedData(ps1.EncryptedData, ps1.Entropy);

                Assert.AreEqual("Hello", ps3.DecryptToString());
            }
        }

        [TestMethod]
        public void TestPBEProtectedString()
        {

            CryptoRandom rand = new CryptoRandom();

            var password = rand.GetASCIIChars(64);

            using (var ps1 = PBEProtectedString.FromString("Hello", password))
            {
                var ps2 = PBEProtectedString.FromString("Hello", password);

                Assert.AreEqual(false, ps1.EncryptedData.SequenceEqual(ps2.EncryptedData));

                Assert.AreEqual("Hello", ps1.DecryptToString());
                Assert.AreEqual("Hello", ps2.DecryptToString());

                var ps3 = PBEProtectedString.FromEncryptedData(ps1.EncryptedData, password, ps1.Salt);

                Assert.AreEqual("Hello", ps3.DecryptToString());
            }
        }


        [TestMethod]
        public void TestHashString()
        {
            var hs = HashString.CreateHMACSHA512("secret");
            Assert.AreEqual("59360d6007ae053929b85baca35bab804f60c08aaaaa77e99c95141b1311d1332fa1ebdd0778c72e34a9f48b0ae4f2c192473a751d69cf9d6862fa597aa24b12", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("43ce2a3ad6c6f2694f7bb94ddb3f0236ab70e9fd667bece66c19a92bc4266125b51bf1ac9901292346746317c3265a729898ab5028eab645c84a047f97afbb5f", hs.ComputeString(new byte[] { 1, 2, 1 }));

            hs = HashString.CreateHMACSHA512("Secret");
            Assert.AreEqual("82bd85b7f29d521d656b5077e6fdc898a5364e33f4b20002f9408484d29479d594173683ed967fd0f313062897e1477f513ac8cca42866c0f9d29375cb0b4673", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("cd441810f657735fe4f05cbc36aec1fc69e0a21bdb51662d1c64d68b11dde8b14b02d64922946ffc182e03e3607da516d923105ac0af2ee598ed6b05bd3151df", hs.ComputeString(new byte[] { 4, 5, 6 }));


            hs = HashString.CreateHMACSHA256("secret");
            Assert.AreEqual("fd8a5cf25311f4dd6ba2b77431ccceccfbdc2df49ff62062078350c44745bbab", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("8455b14265d2b4f7f41ff9d91cd6a7239d6f97d2614e749bd8022cb88cfe4796", hs.ComputeString(new byte[] { 1, 2, 1 }));

            hs = HashString.CreateHMACSHA256("Secret");
            Assert.AreEqual("ff48bdc367a1ceb15610df3d44585ba541795977a1e75d3407dbfbd88331e5d1", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("504f8826a24ed4c69a55870bb6dfe06b0cbfb50524a5ad9e1d45481a1dee3da0", hs.ComputeString(new byte[] { 4, 5, 6 }));



            hs = HashString.CreateHMACSHA1("secret");
            Assert.AreEqual("217ca184982b77046a7df11f170463af98545efe", hs.ComputeString(new byte[] { 1, 2, 3}));
            Assert.AreEqual("a3ce38b87cfc1d83d8d1ce2f934354eaf8709406", hs.ComputeString(new byte[] { 1, 2, 1}));

            hs = HashString.CreateHMACSHA1("Secret");
            Assert.AreEqual("818fb6b8832a67931ab93373a5e3903dba91fd38", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("820e58bd3d346fd9e248981e5e2a8d7ed0568cde", hs.ComputeString(new byte[] { 4, 5, 6 }));


            hs = HashString.CreateSHA512();
            Assert.AreEqual("27864cc5219a951a7a6e52b8c8dddf6981d098da1658d96258c870b2c88dfbcb51841aea172a28bafa6a79731165584677066045c959ed0f9929688d04defc29", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("525454b3b83d2c9ca82be9418ef8933ea00c954f57e391b1ec703a3f84afcd5d942d1de871c0e97f5b00646f6a3176bbcf71f75fab16488263ed3c43c776871b", hs.ComputeString(new byte[] { 1, 2, 1 }));


            hs = HashString.CreateSHA256();
            Assert.AreEqual("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("4912326e465b6efb1d5b1b276e321709d99a506e230a31f3c158c976d4a8a4e8", hs.ComputeString(new byte[] { 1, 2, 1 }));


            hs = HashString.CreateSHA1();
            Assert.AreEqual("7037807198c22a7d2b0807371d763779a84fdfcf", hs.ComputeString(new byte[] { 1, 2, 3 }));
            Assert.AreEqual("0a433b4f5965e3453f48da868296ce002e7eba61", hs.ComputeString(new byte[] { 1, 2, 1 }));

        }




        [TestMethod]
        public void TestClearChars()
        {
            char[] chars = { 'a', 'b', 'c', 'd' };

            bool result = ProtectedString.ClearChars(chars);

            Assert.AreEqual(true, result);

            foreach (var item in chars)
            {
                Assert.AreEqual('\0', item);
            }
        }


        [TestMethod]
        public void TestCryptoRandom()
        {
            CryptoRandom rand = new CryptoRandom();

            var rb1 = rand.NextBytes(4);
            Assert.AreEqual(4, rb1.Length);

            var rb2 = rand.NextBytes(10);
            Assert.AreEqual(10, rb2.Length);

            Assert.AreEqual(0, rand.NextInt(0));
            Assert.AreEqual(0, rand.NextInt(1));

            Assert.ThrowsException<ArgumentOutOfRangeException>(
                () => 
                {
                    rand.NextInt(-10);
                }
                );


        }

        
        [TestMethod]
        public void TestBuildQueryParam()
        {
            var nvc1 = new NameValueCollection();

            nvc1.Add("a", "b");
            nvc1.Add("c", "b");

            Assert.AreEqual("a=b&c=b", HttpUtils.BuildQueryParameters(nvc1));


            var nvc2 = new NameValueCollection();

            nvc2.Add("a", "b");
            nvc2.Add("a", "c");

            Assert.AreEqual("a=b&a=c", HttpUtils.BuildQueryParameters(nvc2));


            var nvc3 = new NameValueCollection();

            nvc3.Add("a", "b");
            nvc3.Add("a", null);
            nvc3.Add("a", "c");

            Assert.AreEqual("a=b&a=c", HttpUtils.BuildQueryParameters(nvc3));


            var nvc4 = new NameValueCollection();

            nvc4.Add("a b", "b&c");
            nvc4.Add("d%e", "f$g");

            Assert.AreEqual("a%20b=b%26c&d%25e=f%24g", HttpUtils.BuildQueryParameters(nvc4));


            var nvc5 = new NameValueCollection();

            nvc5.Add("a", "b");
            nvc5.Add("c", null);
            nvc5.Add("d", "e");

            Assert.AreEqual("a=b&d=e", HttpUtils.BuildQueryParameters(nvc5));

        }


        [TestMethod]
        public void TestBuildUri()
        {
            var uri = new Uri("https://api.example.com/path1/path2");
            var nvc = new NameValueCollection();

            nvc.Add("a", "b");
            nvc.Add("c", "b");

            Assert.AreEqual("https://api.example.com/path1/path2?a=b&c=b", HttpUtils.BuildUri(uri, nvc).AbsoluteUri);


            uri = new Uri("https://api.example.com/path1/path2");
            nvc = new NameValueCollection();

            nvc.Add("a b", "b&c");
            nvc.Add("d%e", "f$g");

            Assert.AreEqual("https://api.example.com/path1/path2?a%20b=b%26c&d%25e=f%24g", HttpUtils.BuildUri(uri, nvc).AbsoluteUri);


            uri = new Uri("https://api.example.com/path1/path2/");
            nvc = new NameValueCollection();

            nvc.Add("a b", "b&c");
            nvc.Add("d%e", "f$g");

            Assert.AreEqual("https://api.example.com/path1/path2/?a%20b=b%26c&d%25e=f%24g", HttpUtils.BuildUri(uri, nvc).AbsoluteUri);



            uri = new Uri("https://api.example.com/path1/path2?a=b&c=d");
            nvc = new NameValueCollection();

            nvc.Add("e", "f");
            nvc.Add("g", "h");

            Assert.AreEqual("https://api.example.com/path1/path2?a=b&c=d&e=f&g=h", HttpUtils.BuildUri(uri, nvc).AbsoluteUri);

            uri = new Uri("http://api.example.com/path1/path2?a=b&c=d");
            nvc = new NameValueCollection();

            nvc.Add("e", "f");
            nvc.Add("g", "h");

            Assert.AreEqual("http://api.example.com/path1/path2?a=b&c=d&e=f&g=h", HttpUtils.BuildUri(uri, nvc).AbsoluteUri);


            uri = new Uri("ftp://api.example.com/path1/path2?a=b&c=d");
            nvc = new NameValueCollection();

            nvc.Add("e", "f");
            nvc.Add("g", "h");

            Assert.ThrowsException<ArgumentException>(
                () =>
                {
                    HttpUtils.BuildUri(uri, nvc);
                }
                );



        }

    }
}
