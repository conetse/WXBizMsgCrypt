// MIT License
//
// Copyright (c) 2018 conetse
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package WXBizMsgCrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

const (
	LETTERDIGITS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	LD_COUNT     = 62
)

const (
	WXBizMsgCrypt_OK                      = 0
	WXBizMsgCrypt_ValidateSignature_Error = -40001
	WXBizMsgCrypt_ParseXml_Error          = -40002
	WXBizMsgCrypt_ComputeSignature_Error  = -40003
	WXBizMsgCrypt_IllegalAesKey           = -40004
	WXBizMsgCrypt_ValidateAppid_Error     = -40005
	WXBizMsgCrypt_EncryptAES_Error        = -40006
	WXBizMsgCrypt_DecryptAES_Error        = -40007
	WXBizMsgCrypt_IllegalBuffer           = -40008
	WXBizMsgCrypt_EncodeBase64_Error      = -40009
	WXBizMsgCrypt_DecodeBase64_Error      = -40010
	WXBizMsgCrypt_GenReturnXml_Error      = -40011
)

var (
	letterDigitArr = []byte(LETTERDIGITS)
)

type (
	XMLParse struct {
		XMLtmpl string
	}

	WXBizMsgCrypt interface {
		EncryptMsg(sReplyMsg string, sNonce string, timestamp int64) (int, string)
		DecryptMsg(sPostData, sMsgSignature string, sTimeStamp int64, sNonce string) (int, string)
	}

	wxBizMsgCrypt struct {
		key   string
		token string
		appid string
	}
)

// sToken: 公众平台上，开发者设置的Token
// sEncodingAESKey: 公众平台上，开发者设置的EncodingAESKey
// sAppId: 企业号的AppId
func NewWXBizMsgCrypt(sToken, sEncodingAESKey, sAppId string) (WXBizMsgCrypt, error) {
	decodeBytes, err := base64.StdEncoding.DecodeString(sEncodingAESKey + "=")
	if err != nil {
		return nil, errors.New("EncodingAESKey err")
	}
	//assert len(key) == 32
	if len(decodeBytes) != 32 {
		return nil, errors.New("EncodingAESKey length err")
	}
	c := &wxBizMsgCrypt{
		key:   string(decodeBytes),
		token: sToken,
		appid: sAppId,
	}
	return c, nil
}

// 将公众号回复用户的消息加密打包
// sReplyMsg: 企业号待回复用户的消息，xml格式的字符串
// sTimeStamp: 时间戳，可以自己生成，也可以用URL参数的timestamp,如为None则自动用当前时间
// sNonce: 随机串，可以自己生成，也可以用URL参数的nonce
// sEncryptMsg: 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串,
// return：成功0，sEncryptMsg,失败返回对应的错误码None
func (c *wxBizMsgCrypt) EncryptMsg(sReplyMsg string, sNonce string, timestamp int64) (int, string) {
	pc := NewPrpcrypt(c.key)
	ret, encryptBytes := pc.encrypt([]byte(sReplyMsg), c.appid)
	if ret != WXBizMsgCrypt_OK {
		return ret, ""
	}
	if timestamp <= 0 {
		timestamp = time.Now().Unix()
	}
	encrypt_text := string(encryptBytes)
	timestampStr := fmt.Sprintf("%d", timestamp)
	// 生成安全签名
	ret, signature := getSHA1(c.token, timestampStr, sNonce, encrypt_text)
	if ret != WXBizMsgCrypt_OK {
		return ret, ""
	}
	xmlParse := NewXMLParse()
	resp_xml := xmlParse.generate(encrypt_text, signature, timestampStr, sNonce)
	return ret, resp_xml
}

// 检验消息的真实性，并且获取解密后的明文
// sMsgSignature: 签名串，对应URL参数的msg_signature
// sTimeStamp: 时间戳，对应URL参数的timestamp
// sNonce: 随机串，对应URL参数的nonce
// sPostData: 密文，对应POST请求的数据
// xml_content: 解密后的原文，当return返回0时有效
// return: 成功0，失败返回对应的错误码
// 验证安全签名
func (c *wxBizMsgCrypt) DecryptMsg(sPostData, sMsgSignature string, sTimeStamp int64, sNonce string) (int, string) {
	// 验证安全签名
	xmlParse := NewXMLParse()
	ret, encrypt, _ := xmlParse.extract(sPostData)
	if ret != WXBizMsgCrypt_OK {
		return ret, ""
	}
	timestampStr := fmt.Sprintf("%d", sTimeStamp)
	ret, signature := getSHA1(c.token, timestampStr, sNonce, encrypt)
	if ret != WXBizMsgCrypt_OK {
		return ret, ""
	}
	if signature != sMsgSignature {
		return WXBizMsgCrypt_ValidateSignature_Error, ""
	}
	pc := NewPrpcrypt(c.key)
	ret, xml_content := pc.decrypt([]byte(encrypt), c.appid)
	return ret, string(xml_content)
}

// 提供提取消息格式中的密文及生成回复消息格式的接口
func NewXMLParse() *XMLParse {
	xp := &XMLParse{
		// xml消息模板
		XMLtmpl: `<xml>
<Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
<MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
<TimeStamp>%(timestamp)s</TimeStamp>
<Nonce><![CDATA[%(nonce)s]]></Nonce>
</xml>`,
	}
	return xp
}

type XmlResources struct {
	XMLName    xml.Name `xml:"xml"`
	Encrypt    string   `xml:"Encrypt"`
	ToUserName string   `xml:"ToUserName"`
}

// 提取出xml数据包中的加密消息
// xmltext: 待提取的xml字符串
// return: 提取出的加密消息字符串
//
func (xp *XMLParse) extract(xmltext string) (int, string, string) {
	var result XmlResources
	err := xml.Unmarshal([]byte(xmltext), &result)
	if err != nil {
		fmt.Println(err)
		return WXBizMsgCrypt_ParseXml_Error, "", ""
	}
	return WXBizMsgCrypt_OK, result.Encrypt, result.ToUserName
}

// 生成xml消息
// encrypt: 加密后的消息密文
// signature: 安全签名
// timestamp: 时间戳
// nonce: 随机字符串
// return: 生成的xml字符串
//
func (xp *XMLParse) generate(encrypt, signature, timestampStr, nonce string) string {
	resp_xml := strings.Replace(xp.XMLtmpl, "%(msg_encrypt)s", encrypt, 1)
	resp_xml = strings.Replace(resp_xml, "%(msg_signaturet)s", signature, 1)
	resp_xml = strings.Replace(resp_xml, "%(timestamp)s", timestampStr, 1)
	resp_xml = strings.Replace(resp_xml, "%(nonce)s", nonce, 1)
	return resp_xml
}

// 计算公众平台的消息签名接口
// 用SHA1算法生成安全签名
// token:  票据
// timestamp: 时间戳
// encrypt: 密文
// nonce: 随机字符串
// return: 安全签名
func getSHA1(token string, timestampStr, nonce, encrypt string) (int, string) {
	sortlist := []string{token, timestampStr, nonce, encrypt}
	sort.Strings(sortlist)
	hashBytes := sha1.Sum([]byte(strings.Join(sortlist, "")))
	hashString := fmt.Sprintf("%x", hashBytes)
	return WXBizMsgCrypt_OK, hashString
}

type Prpcrypt struct {
	key  string
	mode string
}

// 提供接收和推送给公众平台消息的加解密接口
func NewPrpcrypt(key string) *Prpcrypt {
	// 设置加解密模式为AES的CBC模式
	pc := &Prpcrypt{
		key:  key,
		mode: "AES.CBC",
	}
	return pc
}

// s对明文进行加密
// textBytes: 需要加密的明文
// return: 加密得到的字符串
//
func (pc *Prpcrypt) encrypt(textBytes []byte, appid string) (int, []byte) {
	//# 16位随机字符串添加到明文开头
	rand_bytes := pc.get_random_bytes()
	len1 := len(rand_bytes)
	len3 := len(textBytes)
	len_bytes := htonl(len3)
	len2 := len(len_bytes)
	appid_bytes := []byte(appid)
	len4 := len(appid_bytes)
	toBytes := make([]byte, len1+len2+len3+len4)
	copy(toBytes[0:len1], rand_bytes)
	copy(toBytes[len1:(len1+len2)], len_bytes)
	copy(toBytes[(len1+len2):(len1+len2+len3)], textBytes)
	copy(toBytes[(len1+len2+len3):(len1+len2+len3+len4)], appid_bytes)
	// 使用自定义的填充方式对明文进行补位填充
	pkcs7 := NewPKCS7Encoder()
	plantBytes := pkcs7.encode(toBytes)
	// 加密
	keyBytes := []byte(pc.key)
	block, err := aes.NewCipher(keyBytes) //选择加密算法
	if err != nil {
		fmt.Println(err)
		return WXBizMsgCrypt_EncryptAES_Error, []byte{}
	}
	blockModel := cipher.NewCBCEncrypter(block, keyBytes[0:16])
	cipherBytes := make([]byte, len(plantBytes))
	blockModel.CryptBlocks(cipherBytes, plantBytes)
	// 使用BASE64对加密后的字符串进行编码
	dstBytes := make([]byte, base64.StdEncoding.EncodedLen(len(cipherBytes)))
	base64.StdEncoding.Encode(dstBytes, cipherBytes)
	return WXBizMsgCrypt_OK, dstBytes
}

// 对解密后的明文进行补位删除
// cipherBytes: 密文
// return: 删除填充补位后的明文
//
func (pc *Prpcrypt) decrypt(cipherBytes []byte, appid string) (int, []byte) {
	_dstBytes := make([]byte, base64.StdEncoding.DecodedLen(len(cipherBytes)))
	n, err := base64.StdEncoding.Decode(_dstBytes, cipherBytes)
	if err != nil {
		fmt.Println(err)
		return WXBizMsgCrypt_DecodeBase64_Error, []byte{}
	}
	dstBytes := _dstBytes[0:n]
	keyBytes := []byte(pc.key)
	block, err := aes.NewCipher(keyBytes) //选择加密算法
	if err != nil {
		fmt.Println(err)
		return WXBizMsgCrypt_IllegalBuffer, []byte{}
	}
	blockModel := cipher.NewCBCDecrypter(block, keyBytes[0:16])
	plantBytes := make([]byte, len(dstBytes))
	blockModel.CryptBlocks(plantBytes, dstBytes)
	//
	length := len(plantBytes)
	pad := int(uint8(plantBytes[length-1]))
	// 去除16位随机字符串
	content := plantBytes[16:(length - pad)]
	xml_len := ntohl(content[0:4])
	xml_content := content[4:(xml_len + 4)]
	from_appid := content[(xml_len + 4):len(content)]
	if string(from_appid) != appid {
		return WXBizMsgCrypt_ValidateAppid_Error, []byte{}
	}
	return WXBizMsgCrypt_OK, xml_content

}

// 随机生成16位字符串
// return: 16位字符串
//
func (pc *Prpcrypt) get_random_bytes() []byte {
	rander := rand.New(rand.NewSource(time.Now().UnixNano()))
	length := 16
	result := make([]byte, length)
	for i, _ := range result {
		result[i] = letterDigitArr[rander.Intn(LD_COUNT)]
		//result[i] = letterDigitArr[52+((i+1)%10)]
	}
	return result
}

// 提供基于PKCS7算法的加解密接口
type PKCS7Encoder struct {
	block_size int
}

func NewPKCS7Encoder() *PKCS7Encoder {
	p := &PKCS7Encoder{
		block_size: 32,
	}
	return p
}

// 对需要加密的明文进行填充补位
// text: 需要进行填充补位操作的明文
// return: 补齐明文字符串
func (p *PKCS7Encoder) encode(textBytes []byte) []byte {
	length := len(textBytes)
	if length == 0 {
		return []byte{}
	}
	// 计算需要填充的位数
	amount_to_pad := p.block_size - (length % p.block_size)
	if amount_to_pad == 0 {
		amount_to_pad = p.block_size
	}
	// 获得补位所用的字符
	padArr := bytes.Repeat([]byte{byte(amount_to_pad)}, amount_to_pad)
	encTextBytes := make([]byte, length+amount_to_pad)
	copy(encTextBytes, textBytes)
	copy(encTextBytes[length:(length+amount_to_pad)], padArr)
	return encTextBytes
}

// 删除解密后明文的补位字符
// decrypted: 解密后的明文
// return: 删除补位字符后的明文
func (p *PKCS7Encoder) decode(decrypted []byte) []byte {
	length := len(decrypted)
	if length == 0 {
		return []byte{}
	}
	pad := int(uint8(decrypted[length-1]))
	if pad < 1 || pad > 32 {
		pad = 0
	}
	if pad >= length {
		return []byte{}
	}
	return decrypted[0:(length - pad)]
}

func htonl(n int) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(n))
	return data
}

func ntohl(data []byte) int {
	n := binary.BigEndian.Uint32(data[0:4])
	return int(n)
}
