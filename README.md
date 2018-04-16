## WXBizMsgCrypt

本包是 Golang 版本的weixin公众平台发送给公众账号的消息加解密的包.

## Features

对消息进行解密以及加密.

## Installation and Testing

### Install the Go package:
```
go get -u -v github.com/conetse/WXBizMsgCrypt
```
or, you can install it as follow:
```
cd $GOPATH/src/github.com/conetse/
git clone https://github.com/conetse/WXBizMsgCrypt.git
```

### Run the Tests
```
cd $GOPATH/src/github.com/conetse/WXBizMsgCrypt
go test
```

## Example and Usage
```
package main

import (
    "fmt"
    "github.com/conetse/WXBizMsgCrypt"
)

func testWXBizMsgCrypt() {
    encodingAESKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
    token := "spamtest"
    appid := "wx2c2769f8efd9abc2"
    timestamp := int64(1409735669)

    to_xml := ` <xml><ToUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType>  <![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo中文]]></Title><Descript  ion><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>`
    nonce := "1320562132"
    // 测试加密接口
    cryp_test, err := WXBizMsgCrypt.NewWXBizMsgCrypt(token, encodingAESKey, appid)
    if err != nil {
        return
    }
    ret, encrypt_xml := cryp_test.EncryptMsg(to_xml, nonce, timestamp)
    fmt.Println(ret)
    fmt.Println(encrypt_xml)

    // 测试解密接口
    msg_sign := "5d197aaffba7e9b25a30732f161a50dee96bd5fa"
    from_xml := `<xml><ToUserName><![CDATA[gh_10f6c3c3ac5a]]></ToUserName><FromUserName><![CDATA[oyORnuP8q7ou2gfYjqLzSIWZf0rs]]></FromUserName><CreateTime>1409735668</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[abcdteT]]></Content><MsgId>6054768590064713728</MsgId><Encrypt><![CDATA[hyzAe4OzmOMbd6TvGdIOO6uBmdJoD0Fk53REIHvxYtJlE2B655HuD0m8KUePWB3+LrPXo87wzQ1QLvbeUgmBM4x6F8PGHQHFVAFmOD2LdJF9FrXpbUAh0B5GIItb52sn896wVsMSHGuPE328HnRGBcrS7C41IzDWyWNlZkyyXwon8T332jisa+h6tEDYsVticbSnyU8dKOIbgU6ux5VTjg3yt+WGzjlpKn6NPhRjpA912xMezR4kw6KWwMrCVKSVCZciVGCgavjIQ6X8tCOp3yZbGpy0VxpAe+77TszTfRd5RJSVO/HTnifJpXgCSUdUue1v6h0EIBYYI1BD1DlD+C0CR8e6OewpusjZ4uBl9FyJvnhvQl+q5rv1ixrcpCumEPo5MJSgM9ehVsNPfUM669WuMyVWQLCzpu9GhglF2PE=]]></Encrypt></xml>`
    ret, decryp_xml := cryp_test.DecryptMsg(from_xml, msg_sign, timestamp, nonce)
    fmt.Println(ret)
    fmt.Println(decryp_xml)
}

func main() {
    testWXBizMsgCrypt()
}
```

## Links
weixin官方提供的加解密模块的其他语言(C#, C++, Java, PHP, Python)版本 [Download](https://wximg.gtimg.com/shake_tv/mpwiki/cryptoDemo.zip).

## License
This project is under the MIT License.

