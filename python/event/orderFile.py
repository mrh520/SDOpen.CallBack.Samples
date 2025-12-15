from pydantic import BaseModel
from typing import Optional


class OrderFileStatus(BaseModel):
    orderSN: str
    status: int
    filePath: list
    errMsg: Optional[str]
    errType: int


class OrderFileStatusHandle:

    def handle(self, data: OrderFileStatus) -> str:
        """
        处理订单文件状态事件业务逻辑

        :param data: 订单文件状态事件消息体
        :type data: OrderFileStatus
        """

        print("处理订单文件状态事件业务逻辑")
        
        pass
    
        return "success"
