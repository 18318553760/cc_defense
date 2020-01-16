/**
* @program: Go
*
* @description:定义接口类，结构体的方法与之对应
*
* @author: Mr.chen
*
* @create: 2020-01-15 11:26
**/
package ipfilter


//连接过滤器接口定义
type ConnFilter interface {
	//客户端连接建立
	//返回false则关闭连接，同时返回需要关闭连接的原因
	OnConnected(ip string) (bool, string)  // 连接
	GetabnConn(ip string) (int)   // 获取异常次数
}