
/**
* @program: cc_defense
*
* @description: 预防cc攻击操作类
*
* @author: Mr.chen
*
* @create: 2019-11-28 14:45
**/
package main
import (
	"cc_defense/ipfilter"
	"fmt"
	"github.com/thinkeridea/go-extend/exnet"
	"log"
	"net/http"
)
type baseParams struct {
	clientip          string
	allowconn         bool
	allowconnmsg      string
}

func sayhelloName(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()       // 解析 url 传递的参数，对于 POST 则解析响应包的主体（request body）
	// 注意:如果没有调用 ParseForm 方法，下面无法获取表单的数据
	var baseParams = &baseParams{}
	baseParams.clientip = getClientIp(r)
	fmt.Println(baseParams.clientip)
	baseParams.allowconn = true
	baseParams.allowconn, baseParams.allowconnmsg = ipfilter.ConnFilterCtx().OnConnected(baseParams.clientip)
	fmt.Println(baseParams.allowconn,baseParams.allowconnmsg)
	if !baseParams.allowconn {
		//超过3次异常访问，返回500
		fmt.Println("异常")
	}

	fmt.Fprintf(w, "Hello astaxie!") // 这个写入到 w 的是输出到客户端的
}
func getClientIp(r *http.Request) string  {
	ip := exnet.ClientPublicIP(r)
	if ip == ""{
		ip = exnet.ClientIP(r)
	}
	return ip
}
func main() {
	ipfilter.ConnFilterCtx()["cc"] = ipfilter.NewCCConnFilter()
	http.HandleFunc("/", sayhelloName)       // 设置访问的路由
	err := http.ListenAndServe(":8888", nil) // 设置监听的端口
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
