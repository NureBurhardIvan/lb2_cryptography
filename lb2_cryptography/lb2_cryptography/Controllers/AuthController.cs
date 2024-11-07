using Infrastructure;
using Infrastructure.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace lb2_cryptography.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _dbContext;
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public AuthController(AppDbContext dbContext)
        {
            _dbContext = dbContext;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                _publicKey = rsa.ExportParameters(false); // Публічний ключ
                _privateKey = rsa.ExportParameters(true);  // Приватний ключ
            }
        }

        // Відправка публічного ключа клієнту
        [HttpGet("publicKey")]
        public IActionResult GetPublicKey()
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(_publicKey);
            var publicKeyString = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            return Ok(publicKeyString);
        }

        // Прийом зашифрованих даних від клієнта
        [HttpPost("login")]
        public IActionResult Login([FromBody] EncryptedCredentials encryptedCredentials)
        {
            string decryptedUsername, decryptedPassword;

            // Розшифрування логіну та пароля
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(_privateKey);
                decryptedUsername = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(encryptedCredentials.Username), RSAEncryptionPadding.Pkcs1));
                decryptedPassword = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(encryptedCredentials.Password), RSAEncryptionPadding.Pkcs1));
            }

            // Перевірка користувача в базі даних
            var user = _dbContext.Users.SingleOrDefault(u => u.Username == decryptedUsername);
            if (user == null || user.PasswordHash != ComputeHash(decryptedPassword))
            {
                return Unauthorized("Невірний логін або пароль.");
            }

            // Відповідь, що буде зашифрована перед відправкою
            string responseMessage = "Авторизація успішна";
            byte[] encryptedResponse;

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(_publicKey);
                encryptedResponse = rsa.Encrypt(Encoding.UTF8.GetBytes(responseMessage), RSAEncryptionPadding.Pkcs1);
            }

            return Ok(Convert.ToBase64String(encryptedResponse));
        }

        private string ComputeHash(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(bytes);
            }
        }
    }
}
