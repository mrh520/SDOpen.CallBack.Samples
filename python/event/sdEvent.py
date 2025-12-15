from pydantic import BaseModel

class SDEvent(BaseModel):
    """
    盛大回调通知事件
    """

    eventId: str
    eventType: str
    body: object

class EncryptedRequest(BaseModel):
    signature: str
    timestamp: int
    nonce: str
    encrypt: str