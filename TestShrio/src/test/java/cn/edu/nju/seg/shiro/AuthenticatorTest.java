package cn.edu.nju.seg.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticatorTest extends BaseTest{

    private static final Logger logger = LoggerFactory.getLogger(AuthenticatorTest.class);

//    private void login(String configFile) {
//        // 1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
//        Factory<org.apache.shiro.mgt.SecurityManager> factory = new IniSecurityManagerFactory(configFile);
//        // 2、得到SecurityManager实例 并绑定给SecurityUtils
//        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
//        SecurityUtils.setSecurityManager(securityManager);
//        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
//        Subject subject = SecurityUtils.getSubject();
//        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
//        subject.login(token);
//    }
//
//    @Test
//    public void testAllSuccessfulStrategyWithSuccess() {
//        login("classpath:shiro-authenticator-all-success.ini");
//        Subject subject = SecurityUtils.getSubject();
//
//        // 得到一个身份集合，其包含了Realm验证成功的身份信息
//        PrincipalCollection principalCollection = subject.getPrincipals();
//        logger.info(principalCollection.asList().toString());
//        Assert.assertEquals(2, principalCollection.asList().size());
//    }
//
//     @Test(expected = UnknownAccountException.class)
//         public void testAllSuccessfulStrategyWithFail() {
//         login("classpath:shiro-authenticator-all-fail.ini");
//         Subject subject = SecurityUtils.getSubject();
//     }
    
    @Test
    public void testIsPermitted() {
        login("classpath:shiro-authorizer.ini", "zhang", "123");
        // 判断拥有权限：user:create
        Assert.assertTrue(subject().isPermitted("user1:update"));
        Assert.assertTrue(subject().isPermitted("user2:update"));
        // 通过二进制位的方式表示权限
        Assert.assertTrue(subject().isPermitted("+user1+2"));// 新增权限
        Assert.assertTrue(subject().isPermitted("+user1+8"));// 查看权限
        Assert.assertTrue(subject().isPermitted("+user2+10"));// 新增及查看
        Assert.assertFalse(subject().isPermitted("+user1+4"));// 没有删除权限
        Assert.assertTrue(subject().isPermitted("menu:view"));// 通过MyRolePermissionResolver解析得到的权限
    }

    @Test
    public void testIsPermitted2() {
        login("classpath:shiro-jdbc-authorizer.ini", "zhang", "123");
        // 判断拥有权限：user:create
        Assert.assertTrue(subject().isPermitted("user1:update"));
        Assert.assertTrue(subject().isPermitted("user2:update"));
        // 通过二进制位的方式表示权限
        Assert.assertTrue(subject().isPermitted("+user1+2"));// 新增权限
        Assert.assertTrue(subject().isPermitted("+user1+8"));// 查看权限
        Assert.assertTrue(subject().isPermitted("+user2+10"));// 新增及查看
        Assert.assertFalse(subject().isPermitted("+user1+4"));// 没有删除权限
        Assert.assertTrue(subject().isPermitted("menu:view"));// 通过MyRolePermissionResolver解析得到的权限
    }
}
