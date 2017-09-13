using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SBCustomCertStorage;
using SBX509;
using SBXMLAdES;
using SBXMLAdESIntf;
using SBXMLCore;
using SBXMLSec;
using SBXMLSig;
using SBXMLTransform;

namespace EldosMonoPerfTest
{


    class Program
    {
        public static TElX509Certificate Cert { get; set; }
        public static List<TElX509Certificate> Certs { get; set; }
        public static List<long> Elapsed = new List<long>();
        static void Main(string[] args)
        {
            SBUtils.Unit.SetLicenseKey(File.ReadAllText("lic.lic"));


            Cert = new TElX509Certificate();
            Certs = new List<TElX509Certificate>();
            Cert.LoadFromFileAuto("sign.pfx", "password");


            RunLoadTest();
            Console.WriteLine("Finished - press any key to quit");
            Console.ReadLine();
        }

        private static void RunLoadTest()
        {

            ClearOutput();
            Console.WriteLine("===================Running perf with serial do while========================");
            RunSerial();
            ClearOutput();
            Console.WriteLine("===================Running perf with parallel tasks========================");
            RunParallellWithAsyncTasks();
            ClearOutput();
            Console.WriteLine("===================Running perf with parallel tasks and non-shared cert========================");
            RunParallellWithAsyncTasksNonSharedCert();
            ClearOutput();
            Console.WriteLine("===================Running perf with parallel threads========================");
            RunParallellWithAsyncThreads();

        }

        private static void RunSerial()
        {
            var w = Stopwatch.StartNew();

            var count = 100;
            for (int i = 0; i < count; i++)
            {
                CreateXades(i);
            }
            WriteOut(w, count);
        }
        private static void RunParallellWithAsyncTasks()
        {

            var w = Stopwatch.StartNew();
            var tasks = new List<Task>();
            var count = 100;
            for (int i = 0; i < count; i++)
            {
                var i1 = i;
                tasks.Add(Task.Factory.StartNew(() => CreateXades(i1)));
            }
            Task.WaitAll(tasks.ToArray());
            WriteOut(w, count);
        }

        private static void RunParallellWithAsyncTasksNonSharedCert()
        {

            var w = Stopwatch.StartNew();
            var tasks = new List<Task>();
            var count = 100;
            for (int i = 0; i < count; i++)
            {
                var cert = new TElX509Certificate();
                cert.LoadFromFileAuto("sign.pfx", "password");
                Certs.Add(cert);
            }

            for (int i = 0; i < count; i++)
            {
                var i1 = i;
                tasks.Add(Task.Factory.StartNew(() => CreateXades(i1)));
            }
            Task.WaitAll(tasks.ToArray());
            WriteOut(w, count);
        }

        private static void RunParallellWithAsyncThreads()
        {

            var w = Stopwatch.StartNew();
            var tasks = new List<Thread>();
            var count = 100;
            for (int i = 0; i < count; i++)
            {
                var i1 = i;
                tasks.Add(new Thread(() => CreateXades(i1)));
            }
            tasks.ForEach(t => t.Start());
            tasks.ForEach(t => t.Join());
            WriteOut(w, count);
        }

        private static void WriteOut(Stopwatch w, int count)
        {
            Console.WriteLine($"{w.ElapsedMilliseconds} ms total time for {count} signed documents");
            Console.WriteLine($"Fastest signing took {Elapsed.Min()} ms");
            Console.WriteLine($"Slowest signing took {Elapsed.Max()} ms");
            Console.WriteLine($"Average signing took {Elapsed.Average()} ms");
        }

        private static void ClearOutput()
        {
            if (Directory.Exists("output"))
                Directory.Delete("output", true);
            Directory.CreateDirectory("output");
            Elapsed.Clear();
        }

        public static void CreateXades(int i)
        {
            var w = Stopwatch.StartNew();
            TElX509Certificate cert = null;
            //Check if use of static single cert, or cert for this given test
            if (Certs.Any())
                cert = Certs[i];
            else
                cert = Program.Cert;


            var XMLDocument = new TElXMLDOMDocument();
            //Read
            var f = File.Open("input.xml",FileMode.Open,FileAccess.Read,FileShare.Read);
            XMLDocument.LoadFromStream(f);
            f.Close();

            //Sign
            TElXMLSigner Signer;
            TElXAdESSigner XAdESSigner;
            TElXMLKeyInfoX509Data X509KeyData;
            TElXMLDOMNode SigNode;
            TElXMLReference Ref;
            TElXMLReferenceList Refs = new TElXMLReferenceList();
            //Get cert
            X509KeyData = new TElXMLKeyInfoX509Data(true);
            X509KeyData.Certificate = cert;
            Ref = new TElXMLReference();
            Ref.URI = "";
            Ref.ID = "ref-id-1";
            Ref.URINode = XMLDocument.DocumentElement;
            Ref.TransformChain.Add(new TElXMLEnvelopedSignatureTransform());
            Refs.Add(Ref);
            Signer = new TElXMLSigner();

            //cert
            Signer.KeyData = X509KeyData;
            Signer.SignatureType = SBXMLSec.Unit.xstEnveloped;
            Signer.CanonicalizationMethod = SBXMLDefs.Unit.xcmCanon;
            Signer.SignatureMethodType = SBXMLSec.Unit.xmtSig;
            Signer.SignatureMethod = SBXMLSec.Unit.xsmRSA_SHA1;
            Signer.References = Refs;
            Signer.IncludeKey = true;

            X509KeyData = new TElXMLKeyInfoX509Data(false);
            X509KeyData.Certificate = cert;
            Signer.KeyData = X509KeyData;

            XAdESSigner = new TElXAdESSigner();
            Signer.XAdESProcessor = XAdESSigner;
            XAdESSigner.XAdESVersion = SBXMLAdES.Unit.XAdES_v1_4_1;
            XAdESSigner.XAdESForm = SBXMLAdES.Unit.XAdES_BES;
            XAdESSigner.SigningTime = DateTime.Now;
            XAdESSigner.SigningCertificates = new TElMemoryCertStorage();
            XAdESSigner.SigningCertificates.Add(cert, false);

            XAdESSigner.Generate();
            XAdESSigner.QualifyingProperties.XAdESPrefix = "xades";

            TElXMLDataObjectFormat DataObjectFormat = new TElXMLDataObjectFormat(XAdESSigner.XAdESVersion);
            DataObjectFormat.ObjectReference = "#" + Ref.ID;
            DataObjectFormat.MimeType = "text/xml";
            XAdESSigner.QualifyingProperties.SignedProperties.SignedDataObjectProperties.DataObjectFormats.Add(DataObjectFormat);


            Signer.UpdateReferencesDigest();
            Signer.GenerateSignature();

            SigNode = XMLDocument.DocumentElement;

            Signer.Save(ref SigNode);

            //var fs = new MemoryStream();
            var fs = File.OpenWrite("output//" + Guid.NewGuid().ToString("N") + ".xml");
            XMLDocument.SaveToStream(fs);
            fs.Close();
            w.Stop();
            Elapsed.Add(w.ElapsedMilliseconds);

        }
    }
}

