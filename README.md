# go-oauth-starter
封装了osin的oauth服务，采用jwt(json web token)token格式，并采用RSA非对称加密算法对token进行安全保护。
支持授权码模式（还未完成）、密码模式、客户端模式的权限授予，并支持将token等数据持久化。

对外提供了middleware和oauthServer两个代码库，分别用于request server用于jwt的token验证和oauth server的创建。

## Install Govendor & Fresh
用govendor进行依赖管理，fresh进行代码动态监听。

https://github.com/kardianos/govendor

https://github.com/pilu/fresh
```
cd
go get -u github.com/kardianos/govendor
go get -u github.com/pilu/fresh
```

## Start
```
➜  govendor sync
➜  govendor add +external
➜  fresh
```

## 代码结构说明
```
├── common
│   ├── fileUtils.go    //文件解析工具类（后面需要考虑合并到basic framework中）
│   ├── utils.go        //通用工具类（后面需要考虑合并到basic framework中）
│   └── database.go     //数据库初始化工具类（后面需要考虑合并到basic framework中）
├── oauth2               //主逻辑
│   ├── middlewares.go  //封装了jwt的token验证逻辑
│   ├── oauthServer.go  //封装了osin的server初始化逻辑和token\Authorize两个接口的路由方法，oauth-server可以直接调用该路由方法。

```
