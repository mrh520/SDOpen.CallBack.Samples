from pydantic import BaseModel
from typing import Optional


class OrderStatusChangedExtra(BaseModel):
    expressCompany: str
    expressName: str
    expressNo: str


class OrderStatusChangedBody(BaseModel):
    orderSN: str
    orderName: str
    status: int
    remark: Optional[str] = None
    extra: OrderStatusChangedExtra


class OrderStatusHandle:

    def handle(selt, data: OrderStatusChangedBody) -> str:
        """
        处理订单状态变化事件业务逻辑

        :param data: 订单状态变化消息体
        :type data: OrderStatusChangedBody
        """
        print("处理订单状态变化事件业务逻辑")
        
        # TODO...
        pass
    
        return "success"
