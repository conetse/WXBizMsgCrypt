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
	"fmt"
	"testing"
)

func TestWXBizMsgCrypt(t *testing.T) {
	// 1.第三方回复加密消息给公众平台；
	// 2.第三方收到公众平台发送的消息，验证消息的安全性，并对消息进行解密。
	encodingAESKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	token := "spamtest"
	appid := "wx2c2769f8efd9abc2"
	timestamp := int64(1409735669)

	to_xml := ` <xml><ToUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType>  <![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo中文]]></Title><Descript  ion><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>`
	nonce := "1320562132"
	// 测试加密接口
	cryp_test, err := NewWXBizMsgCrypt(token, encodingAESKey, appid)
	if err != nil {
		return
	}
	ret, encrypt_xml := cryp_test.EncryptMsg(to_xml, nonce, timestamp)
	fmt.Println(ret)
	fmt.Println(encrypt_xml)

	msg_sign := "ea7a2ac5580e3c67d663b42c63b976b7e2bf26b9"
	from_xml := `<xml><Encrypt><![CDATA[QCTqNwyPmqRu4xuyqVsja3pIr0TeNW/5tIi3Ul+15UnsdXcZoLmTZJtCxJn7e5lKBp7A5lykhD8Hsejz9M+OBTXLrkuqRD0Ky0fkfk4ZCIZhHc+pWuNZjalZGDQ3tzz2rCfn2pzEHGE3jnSWP4EdLdailWTo/Hz7gxBnLf2xI3xsS9kxyErmv14LhdccB7hVqa224efcb5lT85XKfrku7b4W5L7MA6g8/TYBFrkHCZz9l9sjMgEzNkErAHdayzM6eKCOUm51PQv0Sp3jPjq7NEUi9DZa8nnrz/w3P5clO+Hmf6yqwJZAE26+nGYtltcZmOu8UCZrqZDkAD+MwPeYSGo4C1j6R71zsBwI3sk/Bea52AAGqjvGVPGK3oTvku775T93MwTzjJMZTxX3xF2QrPbbU5pFIBZWF8KW0Giuqui500qRz9Ix5oVK3TK4ZCCZpHJelUvy5gcP4ldbDStZhQaM21pdlitL6Kt/GucIpIWHkxiObKu1pBfU94cR0ZCgoja8E6xtx+cGMIgCN33/QHkwM+xeb6rCF0HhDZwd9TwdetxpRbqRDkfzc+LaeoF8HHbFhK+3tKP9qZBAdZm1v4YUFK2db1juaoyXHAXFDn3I8PZ5zSP8vddBDSfoLgv+]]></Encrypt><MsgSignature><![CDATA[ea7a2ac5580e3c67d663b42c63b976b7e2bf26b9]]></MsgSignature><TimeStamp>1409735669</TimeStamp><Nonce><![CDATA[1320562132]]></Nonce></xml>`

	// 测试解密接口
	//msg_sign := "5d197aaffba7e9b25a30732f161a50dee96bd5fa"
	//from_xml := `<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName><FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName><CreateTime>1409735668</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[abcdteT]]></Content><MsgId>6054768590064713728</MsgId><Encrypt><![CDATA[hyzAe4OzmOMbd6TvGdIOO6uBmdJoD0Fk53REIHvxYtJlE2B655HuD0m8KUePWB3+LrPXo87wzQ1QLvbeUgmBM4x6F8PGHQHFVAFmOD2LdJF9FrXpbUAh0B5GIItb52sn896wVsMSHGuPE328HnRGBcrS7C41IzDWyWNlZkyyXwon8T332jisa+h6tEDYsVticbSnyU8dKOIbgU6ux5VTjg3yt+WGzjlpKn6NPhRjpA912xMezR4kw6KWwMrCVKSVCZciVGCgavjIQ6X8tCOp3yZbGpy0VxpAe+77TszTfRd5RJSVO/HTnifJpXgCSUdUue1v6h0EIBYYI1BD1DlD+C0CR8e6OewpusjZ4uBl9FyJvnhvQl+q5rv1ixrcpCumEPo5MJSgM9ehVsNPfUM669WuMyVWQLCzpu9GhglF2PE=]]></Encrypt></xml>`
	ret, decryp_xml := cryp_test.DecryptMsg(from_xml, msg_sign, timestamp, nonce)
	fmt.Println(ret)
	fmt.Println(decryp_xml)
}
