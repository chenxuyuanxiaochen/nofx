package api

import (
    "encoding/base64"
    "encoding/json"
    "log"
    "net/http"
    "nofx/crypto"

    "github.com/gin-gonic/gin"
)

// CryptoHandler 加密 API 處理器
type CryptoHandler struct {
	cryptoService *crypto.CryptoService
}

// NewCryptoHandler 創建加密處理器
func NewCryptoHandler(cryptoService *crypto.CryptoService) *CryptoHandler {
	return &CryptoHandler{
		cryptoService: cryptoService,
	}
}

// ==================== 公鑰端點 ====================

// HandleGetPublicKey 獲取伺服器公鑰
func (h *CryptoHandler) HandleGetPublicKey(c *gin.Context) {
	publicKey := h.cryptoService.GetPublicKeyPEM()

	c.JSON(http.StatusOK, map[string]string{
		"public_key": publicKey,
		"algorithm":  "RSA-OAEP-2048",
	})
}

// ==================== 加密數據解密端點 ====================

// HandleDecryptSensitiveData 解密客戶端傳送的加密数据
func (h *CryptoHandler) HandleDecryptSensitiveData(c *gin.Context) {
    var payload crypto.EncryptedPayload
    if err := c.ShouldBindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
        return
    }

    // 仅允许已认证用户调用
    userID := c.GetString("user_id")
    if userID == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证或缺少用户信息"})
        return
    }

    // 强制校验 AAD（必须包含且 userId 必须匹配当前用户）
    if payload.AAD == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "缺少AAD，拒绝解密"})
        return
    }
    aadBytes, err := base64.RawURLEncoding.DecodeString(payload.AAD)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "AAD格式错误"})
        return
    }
    var aadData crypto.AADData
    if err := json.Unmarshal(aadBytes, &aadData); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "AAD解析失败"})
        return
    }
    if aadData.UserID == "" || aadData.UserID != userID {
        c.JSON(http.StatusForbidden, gin.H{"error": "AAD用户不匹配，拒绝解密"})
        return
    }

    // 解密
    decrypted, err := h.cryptoService.DecryptSensitiveData(&payload)
    if err != nil {
        log.Printf("❌ 解密失敗: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption failed"})
        return
    }

	c.JSON(http.StatusOK, map[string]string{
		"plaintext": decrypted,
	})
}

// ==================== 審計日誌查詢端點 ====================

// 删除审计日志相关功能，在当前简化的实现中不需要

// ==================== 工具函數 ====================

// isValidPrivateKey 驗證私鑰格式
func isValidPrivateKey(key string) bool {
	// EVM 私鑰: 64 位十六進制 (可選 0x 前綴)
	if len(key) == 64 || (len(key) == 66 && key[:2] == "0x") {
		return true
	}
	// TODO: 添加其他鏈的驗證
	return false
}
