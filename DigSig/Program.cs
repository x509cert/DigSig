using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Text;

if (args.Length != 2)
{
    Console.WriteLine("Usage: DigSig s|v filename");
    return;
}

if (args[0] == "s")
{
    var data = File.ReadAllBytes(args[1]);
    var signingCert = LoadCertificate("mikehow@microsoft.com");
    var signedData = SignData(data, signingCert);
    File.WriteAllBytes(args[1] + ".p7s", signedData);
}
else if (args[0] == "v")
{
    var filename = args[1];
    if (!filename.EndsWith(".p7s"))
    {
        Console.WriteLine("Invalid file type.");
        return;
    }

    var signedData = File.ReadAllBytes(filename);
    var valid = VerifyData(signedData);
    Console.WriteLine($"Signature is valid: {valid}");
    
    if (valid) 
        DisplayContent(signedData);
}
else
{
    Console.WriteLine("Invalid command.");
}

static X509Certificate2 LoadCertificate(string subjectName)
{
    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadOnly);
    var certs = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, false);
    store.Close();

    if (certs.Count == 0)
        throw new Exception("Certificate not found.");

    return certs[0];
}

static byte[] SignData(byte[] data, X509Certificate2 cert)
{
    var content = new ContentInfo(data);
    var signedCms = new SignedCms(content, false);
    var signer = new CmsSigner(cert);
    signedCms.ComputeSignature(signer);

    return signedCms.Encode();
}
static bool VerifyData(byte[] signedData)
{
    var signedCms = new SignedCms();
    signedCms.Decode(signedData);

    try
    {
        signedCms.CheckSignature(true);
        return true;
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.Message);
        return false;
    }
}

static bool DisplayContent(byte[] signedData)
{
    var signedCms = new SignedCms();
    signedCms.Decode(signedData);
    var content = signedCms.ContentInfo;

    Console.WriteLine($"Content length: {content.Content.Length}");
    Console.WriteLine(content.Content.Length > 0 ? Encoding.UTF8.GetString(content.Content) : "");    
    Console.WriteLine($"Signer count: {signedCms.SignerInfos.Count}");
    foreach (var signerInfo in signedCms.SignerInfos)
    {
        Console.WriteLine($"Signer: {signerInfo.Certificate.Subject}");
    }

    return true;
}
