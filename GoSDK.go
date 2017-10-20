package gogoal

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"encoding/hex"
	"unicode/utf8"
)

func HttpGet(url string, appkey string, sercret string, apiName string, apiParam string, timeout int) (data string, err error) {
	param := makeParam("GET", apiName, apiParam, appkey, sercret)
	temp := url + "/" + apiName + "?" + param
	client := &http.Client{
		Timeout: time.Duration(time.Duration(timeout) * time.Millisecond),
	}
	resp, err := client.Get(temp)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return string(body), err
}

func HttpPost(urlstr string, appkey string, secret string, apiName string, apiParam string, timeout int) (data string, err error) {
	param := makeParam("POST", apiName, apiParam, appkey, secret)
	temp := fmt.Sprintf("%s/%s", urlstr, apiName)
	client := &http.Client{
		Timeout: time.Duration(time.Duration(timeout) * time.Millisecond),
	}
	req, err := http.NewRequest("POST", temp, strings.NewReader(param))
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return string(body), err
}

/*******************************************************************************************
makeParam
	生成包含签名(sign)的URL完整参数，签名规则如下：
		1.) 生成HTTP请求方式(GET或者POST)的字符串(全部大写)
		2.) 生成API名称(如:v1/test/get_pdp)的URL编码字符串(参考UrlEncode函数)
		3.) 将URL参数(包含app_key和time_stamp，但sign除外)的值编码(参考CodePayValue函数)，
			然后将参数按key进行字典升序排列并URL编码(参考UrlEncode函数)生成新的字符串
		4.) 将以上三步生成的字符串按顺序用&拼接成新的字符串
		5.) 将以上字符串用HMAC-SHA1算法加密得到加密字符串
		6.) 将加密字符串用Base64算法编码得到sign(签名)参数的值
*******************************************************************************************/
func makeParam(method string, apiName string, apiParam string, appKey string, appSercret string) (param string) {
	var params string
	var signSrc string
	params = apiParam
	if len(params) > 0 {
		params = params + "&"
	}
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	params = fmt.Sprintf("app_key=%s&%stime_stamp=%s", appKey, params, timestamp)
	mapParam := make(map[string]string)
	paramSpilt := strings.Split(params, "&")
	for _, value := range paramSpilt {
		param := strings.Split(value, "=")
		if len(param) == 2 {
			if param[0] != "sign" {
				mapParam[param[0]] = param[1]
			}
		}
	}
	keys := make([]string, len(mapParam))
	count := 0
	for k := range mapParam {
		keys[count] = k
		count++
	}
	sort.Strings(keys)
	var strParams string
	count = 0
	for _, value := range keys {
		if count != 0 {
			strParams = strParams + "&"
		}
		strParams = strParams + value + "=" + encodeParamValue(mapParam[value])
		count++
	}
	signSrc = fmt.Sprintf("%s&%s&%s", strings.ToUpper(method), url.QueryEscape(apiName), url.QueryEscape(strParams))
	h := hmac.New(sha1.New, []byte(appSercret))
	h.Write([]byte(signSrc))
	encodeString := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s", h.Sum(nil))))
	mapParam["sign"] = encodeString
	count = 0
	keys = make([]string, len(mapParam))
	for k := range mapParam {
		keys[count] = k
		count++
	}
	sort.Strings(keys)
	v := url.Values{}
	for _, value := range keys {
		v.Set(value, mapParam[value])
	}
	strParams = v.Encode()
	return strParams
}

func isalpha(c rune) bool {
	if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
		return true
	}
	return false
}

/*********************************************************************************
encodeParamValue
	对url参数值进行编码：传入的参数值字符串必须为utf-8编码，编码规则如下：
		1.) 数字('0'-'9')和英文字母('a'-'z','a'-'z')不编码
		2.) 星号('*'),叹号('!'),左括弧('('),右括弧(')')四个半角符号不编码
		3.) 其它字符将utf-8编码最后一个字节编码为%xy(字节的16进制表示)
*********************************************************************************/
func encodeParamValue(value string) string {
	var ret string
	if utf8.ValidString(value) {
		text := []rune(value)
		for _, c := range text {
			if isalpha(c) || c == '*' || c == '(' || c == ')' || c == '!' {
				ret += string(c)
			} else {
				b := make([]byte, utf8.UTFMax)
				temp := make([]byte,1)
				i := utf8.EncodeRune(b,c)
				temp[0] = b[i-1]
				ret += "%" + strings.ToUpper(hex.EncodeToString(temp))
			}
		}
	}
	return ret
}