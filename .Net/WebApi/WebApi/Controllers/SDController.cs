using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers;

[Route("[controller]/[action]")]
public class SDController : Controller
{
    [HttpPost]
    public string Callback([FromBody] SDOpenCallbackInput input)
    {
        try
        {
            CallbackCrypto callbackCrypto = new CallbackCrypto("nMM/aZcZVw7NVm//n+9pGg==", "appId");

            string decryptMsg = callbackCrypto.GetDecryptMsg(input.Signature, input.Timestamp, input.Nonce, input.Encrypt);

            Console.WriteLine(decryptMsg);

            return "success";
        }
        catch (Exception ex)
        {
            throw;
        }
    }

    public class SDOpenCallbackInput
    {
        public string AppId { get; set; }
        public string Timestamp { get; set; }
        public string Signature { get; set; }
        public string Nonce { get; set; }
        public string Encrypt { get; set; }
    }
}
