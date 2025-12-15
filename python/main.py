from utils.sdCllbackCrypto import CallbackCrypto
from fastapi import FastAPI, HTTPException
import uvicorn
import json
from event.orderStatus import OrderStatusChangedBody, OrderStatusHandle
from event.sdEvent import EncryptedRequest, SDEvent
from event.orderFile import OrderFileStatus, OrderFileStatusHandle


# 请求数据模型


encodingAesKey = "nMM/aZcZVw7NVm//n+9pGg=="
appId = "appId"

sdCrypto = CallbackCrypto(encoding_aes_key=encodingAesKey, client_id=appId)

app = FastAPI()


# 解密接口
@app.post("/sd/callback")
async def decrypt_message(request: EncryptedRequest) -> str:
    try:
        # 验证签名
        if not sdCrypto.verify_signature(
            request.signature, request.timestamp, request.nonce, request.encrypt
        ):
            raise HTTPException(status_code=400, detail="Invalid signature")

        # 解密消息
        decrypted_msg = sdCrypto.decrypt(request.encrypt)

        event = SDEvent.model_validate(json.loads(decrypted_msg))

        if event.eventType == "orderStatus":

            orderStatusHandle = OrderStatusHandle()

            body = OrderStatusChangedBody.model_validate(event.body)  # 动态转换

            return orderStatusHandle.handle(body)

        elif event.eventType == "orderFile":

            orderFileStatusHandle = OrderFileStatusHandle()

            body = OrderFileStatus.model_validate(event.body)  # 动态转换

            return orderFileStatusHandle.handle(body)

        return "faild"
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    # 配置服务参数（host、port等）
    uvicorn.run(
        app="__main__:app",  # 指向当前模块的app实例
        host="localhost",  # 允许外部访问
        port=8000,  # 端口号
        reload=True,  # 开发模式下自动重载（生产环境建议关闭）
    )
