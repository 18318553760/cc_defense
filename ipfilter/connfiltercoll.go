/**
* @program: Go
*
* @description:防御攻击操作类，过滤器集合类，管理一组过滤器，提供统一的外部调用接口，实际也可以直接调用其他的类便可实践功能，此处将上面的接口封装成一个集合，每一个访问对应的结合
*
* @author: Mr.chen
*
* @create: 2020-01-15 11:26
**/
package ipfilter
import "fmt"
type ConnFilterColl map[string]ConnFilter
func (filters ConnFilterColl) OnConnected(ip string) (bool, string) { // 循环类型，cc,黑明单
	fmt.Println(filters)
	for _, f := range filters {
		ret, msg := f.OnConnected(ip)
		if !ret {
			return ret, msg
		} else if ret && msg != "" {
			return ret, msg
		}
	}
	return true, ""
}

func (filters ConnFilterColl) GetabnConn(ip string) (int) {  // 返回cc异常次数
	for _, f := range filters {
		ret := f.GetabnConn(ip)
		return ret
	}
	return 0
}

var filterCtx ConnFilterColl

//初始化过滤器上下文
func init() {
	filterCtx = make(map[string]ConnFilter)
}

func ConnFilterCtx() ConnFilterColl {
	return filterCtx
}
