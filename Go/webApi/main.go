package main

import (
	"fmt"
	"net/http"
	callbackcrypto "webApi/utils"

	"github.com/gin-gonic/gin"
)

type SDOpenCallbackReq struct {
	AppId     string
	Timestamp string
	Signature string
	Nonce     string
	Encrypt   string
}

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "hello SDOpen!")
	})

	r.POST("/sd/callback", func(ctx *gin.Context) {
		var json SDOpenCallbackReq

		if err := ctx.ShouldBindJSON(&json); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		encodingAesKey := "nMM/aZcZVw7NVm//n+9pGg==" // 替换成自己的 encodingAesKey
		appId := "appId"                             // 替换成自己的 appId

		crypto, err := callbackcrypto.NewCallbackCrypto(encodingAesKey, appId)
		if err != nil {
			fmt.Printf("Failed to initialize CallbackCrypto: %v\n", err)
			return
		}

		decrypted, err := crypto.GetDecryptMsg(json.Signature, json.Timestamp, json.Nonce, json.Encrypt)

		if err != nil {
			fmt.Printf("\nDecrypted Message: %v\n", err.Error())
		}

		fmt.Printf("\nDecrypted Message: %s\n", decrypted)

		// TODO 业务逻辑

		ctx.String(http.StatusOK, "success")
	})

	r.Run(":8000")
}
