# 概述

## 前言

在大学的时候，大家有没有过抢课的经验，每到抢课的时候，就一直打不开学校的网页，这是因为在某个时间点融入了大量的流量，，不断的向服务器发送数据包，导致服务器超负荷了，甚至是宕机崩溃。

## cc攻击原理

CC(ChallengeCollapsar，挑战黑洞)攻击是DDoS攻击的一种类型，使用代理服务器向受害服务器发送大量貌似合法的请求。CC根据其工具命名，攻击者使用代理机制，利用众多广泛可用的免费代理服务器发动DDoS攻击。许多免费代理服务器支持匿名模式，这使追踪变得非常困难。

CC攻击的原理就是攻击者控制某些主机不停地发大量数据包给对方服务器造成服务器资源耗尽，一直到宕机崩溃。CC主要是用来攻击页面的，每个人都有这样的体验：当一个网页访问的人数特别多的时候，打开网页就慢了，CC就是模拟多个用户（多少线程就是多少用户）不停地进行访问那些需要大量数据操作（就是需要大量CPU时间）的页面，造成服务器资源的浪费，CPU长时间处于100%，永远都有处理不完的连接直至就网络拥塞，正常的访问被中止。 

## 防CC攻击

1、服务器垂直扩展和水平扩容

资金允许的情况下，这是最简单的一种方法，本质上讲，这个方法并不是针对CC攻击的，而是提升服务本身处理并发的能力，但确实提升了对CC攻击的承载能力。垂直扩展：是指增加每台服务器的硬件能力，如升级CPU、增加内存、升级SSD固态硬盘等。水平扩容：是指通过增加提供服务的服务器来提升承载力。上述扩展和扩容可以在服务的各个层级进行，包括：应用服务器、数据库服务器和缓存服务器等等。

2、数据缓存(内存级别，不要用文件)

对于服务中具备高度共性，多用户可重用，或单用户多次可重用的数据，一旦从数据库中检索出，或通过计算得出后，最好将其放在缓存中，后续请求均可直接从缓存中取得数据，减轻数据库的检索压力和应用服务器的计算压力，并且能够快速返回结果并释放进程，从而也能缓解服务器的内存压力。要注意的是，缓存不要使用文件形式，可以使用redis、mem—cached等基于内存的nosql缓存服务，并且与应用服务器分离，单独部署在局域网内。局域网内的网络IO肯定比起磁盘IO要高。为了不使局域网成为瓶颈，千兆网络也是有必要的。

3、页面静态化

与数据缓存一样，页面数据本质上也属于数据，常见的手段是生成静态化的html页面文件，利用客户端浏览器的缓存功能或者服务端的缓存服务，以及CDN节点的缓冲服务，均可以降低服务器端的数据检索和计算压力，快速响应结果并释放连接进程。

4、用户级别的调用频率限制

不管服务是有登陆态还是没登陆态，基于session等方式都可以为客户端分配唯一的识别ID(后称作SID)，服务端可以将SID存到缓存中。当客户端请求服务时，如果没有带SID(cookie中或请求参数中等)，则由服务端快速分配一个并返回。可以的话，本次请求可以不返回数据，或者将分配SID独立出业务服务。当客户端请求时带了合法SID(即SID能在服务端缓存中匹配到)，便可以依据SID对客户端进行频率限制。而对于SID非法的请求，则直接拒绝服务。相比根据IP进行的频率限制，根据SID的频率限制更加精准可控，可最大程度地避免误杀情况。

5、IP限制

最后，IP限制依然可以结合上述规则一起使用，但是可以将其前置至)JCb层的防火墙或负载均衡器上去做，并且可以调大限制的阈值，防止恶意访问穿透到应用服务器上，造成应用服务器压力。

## golang抵御cc做法

### 定义接口

```
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
```

### 定义结构体，实现接口的方法

```
/**
* @program: Go
*
* @description: 结构体继续接口
*
* @author: Mr.chen
*
* @create: 2020-01-15 11:28
**/
package ipfilter
import (
	"fmt"
	"github.com/astaxie/beego/logs"
	"sync"
	"time"
)
const (
	maxConn  = 6            //同IP最大异常访问数
	checkTimeReset = 120     //重置计数器间隔
	checkTimeDiff = 5      //异常时间差
)

//cc过滤
type CCConnFilter struct {
	currentConn    map[string]int          //当前连接数
	abnConn        map[string]int          //异常连接数
	connTimelog    map[string]time.Time    //当前访问时间记录
	locker         sync.Mutex              //访问同步锁
}

//创建对象实例
// maxConnCount 同ip最大连接数
func NewCCConnFilter() *CCConnFilter {
	ccf := CCConnFilter{}
	ccf.currentConn = make(map[string]int)
	ccf.abnConn = make(map[string]int)
	ccf.connTimelog = make(map[string]time.Time)
	ccf.locker = sync.Mutex{}
	go func() {
		for {
			time.Sleep(time.Duration(time.Second.Nanoseconds() * checkTimeReset))
			//fmt.Println("清理访问计数器...")
			ccf.locker.Lock()
			ccf.currentConn = make(map[string]int)
			ccf.abnConn = make(map[string]int)
			ccf.connTimelog = make(map[string]time.Time)
			ccf.locker.Unlock()
		}
	}()
	return &ccf
}

func (filter *CCConnFilter) OnConnected(ip string) (bool, string) {

	filter.locker.Lock()
	defer filter.locker.Unlock()
	t := time.Now()
	if v, ok := filter.currentConn[ip]; !ok { // 第一次访问 v是获取的值
		filter.currentConn[ip] = 1
		filter.abnConn[ip] = 0
		filter.connTimelog[ip] = t
	} else {
		filter.currentConn[ip]++
		//先取上次更新过的时间
		lastconntime := filter.connTimelog[ip]
		//每10次访问更新1次时间
		fmt.Println(v)
		if (v)%10 == 9 {
			filter.connTimelog[ip] = t
			//明确每10次访问的时间间隔时长低于10s视为异常访问
			if t.Sub(lastconntime) < time.Second * checkTimeDiff {
				filter.abnConn[ip]++
				if filter.abnConn[ip] <= maxConn {
					logs.Warning(fmt.Sprintf("IP:%s,访问成功,LastTime:%s,CurrentTime:%s,间隔:%s,访问过于频繁!\n",
						ip, lastconntime.Format("2006-01-02 15:04:05"),
						t.Format("2006-01-02 15:04:05"), t.Sub(lastconntime)))
					return true, "Warning:您的访问过于频繁!"
				}
			}
		}
		if filter.abnConn[ip] >= maxConn {
			logs.Warning(fmt.Sprintf("IP:%s,拒绝访问,返回500状态,异常访问次数:%d\n", ip, filter.abnConn[ip]))
			return false, "拒绝访问!"
		}
	}
	return true, ""
}

func (filter *CCConnFilter) GetabnConn(ip string) (int) {
	return filter.abnConn[ip]
}
```

### 定义集合，实现cc防御，可扩展其他的方法

```
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

```

### 主程序，搭建web服务器

```

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

```