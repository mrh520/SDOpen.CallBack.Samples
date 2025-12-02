from callbackCrypto import CallbackCrypto
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn


# 请求数据模型
class EncryptedRequest(BaseModel):
    signature: str
    timestamp: int
    nonce: str
    encrypt: str


encodingAesKey = "nMM/aZcZVw7NVm//n+9pGg=="
appId = "appId"

sdCrypto = CallbackCrypto(encoding_aes_key=encodingAesKey, client_id=appId)

app = FastAPI()


# 解密接口
@app.post("/sd/callback")
async def decrypt_message(request: EncryptedRequest):
    try:
        # 验证签名
        if not sdCrypto.verify_signature(
            request.signature, request.timestamp, request.nonce, request.encrypt
        ):
            raise HTTPException(status_code=400, detail="Invalid signature")

        # 解密消息
        decrypted_msg = sdCrypto.decrypt(request.encrypt)
        return {"status": "success", "decrypted_message": decrypted_msg}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


if __name__ == "__main__":
    # 配置服务参数（host、port等）
    uvicorn.run(
        app="__main__:app",  # 指向当前模块的app实例
        host="localhost",  # 允许外部访问
        port=8000,  # 端口号
        reload=True,  # 开发模式下自动重载（生产环境建议关闭）
    )
