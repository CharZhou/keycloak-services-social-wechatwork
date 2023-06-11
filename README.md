# keycloak-services-social-wechat-work

Keycloak企业微信登录插件

Keycloak 21.1.1 测试通过

```bash
# build from source
mvn clean package

# add the jar to the Keycloak server (create `providers` folder if needed)
mkdir -p $KEYCLOAK_HOME/providers/
cp target/keycloak-services-social-wework.jar $KEYCLOAK_HOME/providers/
```
