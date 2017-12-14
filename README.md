# spring-boot-starter-cas-client
Spring boot quickly integrates Cas Client and solves the problem of single point boarding in cluster clients

At present, the client relies on spring-session + redis to do distributed session storage, and ZK is integrated by default to do client node registration.

#Mode of use
```java
@SpringBootApplication
@EnableCas
public class Application {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(Application.class, args);
	}
}

```


application.properties configuration<br>

```yaml
spring.application.name=myApplication   #ZK acquiescence by default for this configuration as a node name, so it is recommended to configure<br>
server.port=30602    #ZK acquiescence by taking this configuration as a node name splicing, so it is recommended to configure
<br>

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
```


The parent of this project can be modified by itself. I use the upper POM.xml.
```java
<parent>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-parent</artifactId>
	<version>1.5.6.RELEASE</version>
</parent>
```



Donation developer (ETH)<br>
0x23b96A20Fae711ED6D286feAEED437a6831e3dD7