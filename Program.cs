using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DigitalniPotpis
{
    internal class Program
    {
        public static string GenerirajPotpis(string podaciZaPotpis, string putPrivatniKljuc, string lozinka = null)
        {
            try
            {
                string privatniKljucPem = File.ReadAllText(putPrivatniKljuc);
                RSA privatniKljuc = RSA.Create();

                if (lozinka != null)
                {
                    privatniKljuc.ImportFromEncryptedPem(privatniKljucPem.ToCharArray(), lozinka.ToCharArray());
                }
                else
                {
                    privatniKljuc.ImportFromPem(privatniKljucPem.ToCharArray());
                }

                byte[] podaciBajtovi = Encoding.UTF8.GetBytes(podaciZaPotpis);
                byte[] potpisBajtovi = privatniKljuc.SignData(podaciBajtovi, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return Convert.ToBase64String(potpisBajtovi);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Greška kod generiranja potpisa: {ex.Message} ");
                return null;
            }
        }

        public static bool ProvjeriPotpis(string podaciZaProvjeru, string potpis, string putJavniKljuc)
        {
            try
            {
                string javniKljucPem = File.ReadAllText(putJavniKljuc);
                RSA javniKljuc = RSA.Create();
                javniKljuc.ImportFromPem(javniKljucPem.ToCharArray());

                byte[] podaciBajtovi = Encoding.UTF8.GetBytes(podaciZaProvjeru);
                byte[] potpisBajtovi = Convert.FromBase64String(potpis);

                return javniKljuc.VerifyData(podaciBajtovi, potpisBajtovi, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Greška kod provjere potpisa: {ex.Message} ");
                return false;
            }
        }

        public static string GenerateSignCertificate(string dataToSign, string certificatePath, string certificatePass)
        {
            try
            {
                var certifikat = new X509Certificate2(certificatePath, certificatePass, X509KeyStorageFlags.Exportable);
                var originalData = Encoding.UTF8.GetBytes(dataToSign);

                using (var rsa = certifikat.GetRSAPrivateKey())
                {
                    if (rsa == null)
                        throw new Exception("Privatni ključ nije pronađen u certifikatu.");

                    var signedData = rsa.SignData(originalData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return Convert.ToBase64String(signedData);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Greška kod generiranja potpisa s certifikatom: {ex.Message}");
                return null;
            }
        }

        public static bool CheckSignCertificate(string dataToVerify, string signature, string certificatePath)
        {
            try
            {
                var certifikat = new X509Certificate2(certificatePath);
                var dataToVerifyBytes = Encoding.UTF8.GetBytes(dataToVerify);
                var signatureBytes = Convert.FromBase64String(signature);

                using (var rsa = certifikat.GetRSAPublicKey())
                {
                    return rsa.VerifyData(dataToVerifyBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Greška kod provjere potpisa s certifikatom: {ex.Message}");
                return false;
            }
        }
        static void Main(string[] args)
        {
            string podaciZaPotpis = "Podaci za potpis";
            string putanjaDoMape = @"D:\PraksaKodovi\DigitalniPotpis\Keys\";

            string putPrivatniKljuc = Path.Combine(putanjaDoMape, "PrivateKey.pem");
            string putJavniKljuc = Path.Combine(putanjaDoMape, "PublicKey.pem");

            string putCertifikat = Path.Combine(putanjaDoMape, "PrivateKeyPfxFile.pfx");
            string certifikatPass = "test";
            string lozinkaPrivatnogKljuca = "test";

            string potpis = GenerirajPotpis(podaciZaPotpis, putPrivatniKljuc, lozinkaPrivatnogKljuca);
            Console.WriteLine($"Generirani potpis: {potpis}");

            bool vazeciPotpis = ProvjeriPotpis(podaciZaPotpis, potpis, putJavniKljuc);
            Console.WriteLine($"Je li potpis važeći? {vazeciPotpis}");

            string potpisCertifikat = GenerateSignCertificate(podaciZaPotpis, putCertifikat, certifikatPass);
            Console.WriteLine($"Generirani potpis s certifikatom: {potpisCertifikat}");

            bool vazeciCertifikat = CheckSignCertificate(podaciZaPotpis, potpisCertifikat, putCertifikat);
            Console.WriteLine($"Je li potpis valjan (certifikat)? {vazeciCertifikat}");
        }
    }
}