# spring-boot-starter-cas-client
spring boot 快速集成Cas Client，并解决集群客户端单点登出的问题

目前客户端默认依赖spring-session + redis做分布式session存储,默认集成zk做客户端节点注册（用于单点登出时动态分发logoutRequest）


application.properties 配置如下<br>


spring.application.name=myApplication   #zk默认取这条配置作为节点名，所以建议配置<br>
server.port=30602    #zk默认取这条配置作为节点名拼接，所以建议配置<br>

#Cas<br>
cas.server.url=https://passport.domain.com
cas.server.loginUrl=${cas.server.url}/login
cas.server.logoutUrl=${cas.server.url}/logout?service=${cas.client.url}
cas.client.url=http://client.domain.com

#Zookeeper<br>
zookeeper.servers=130.252.100.20:2181

#Spring Session<br>
spring.session.store-type=redis
server.session.timeout=3600




在兴趣的驱动下,写一个`免费`的东西，有欣喜，也还有汗水，希望你喜欢我的作品，同时也能支持一下。
当然，有钱捧个钱场(微信支付），没钱捧个人场，谢谢各位。

##捐助开发者
![pay](http://cdn.51szzc.com/custom/pay2luheng.png)