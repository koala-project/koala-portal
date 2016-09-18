package com.koala.protal.servlet;

import com.alibaba.dubbo.config.ApplicationConfig;
import com.alibaba.dubbo.config.ReferenceConfig;
import com.alibaba.dubbo.config.RegistryConfig;
import com.koala.protal.common.ApiConfig;
import com.koala.protal.common.KeysConfig;
import com.koala.utils.gateway.core.ApiManager;
import com.koala.utils.gateway.entity.CommonConfig;
import com.koala.utils.gateway.entity.CompileConfig;
import org.apache.catalina.loader.WebappClassLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.io.File;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.jar.JarFile;

/**
 * @Author Liuyf
 * @Date 2016-09-13
 * @Time 17:58
 * @Description
 */
@WebListener
public class StartupListener implements ServletContextListener {

    public static final Logger logger = LoggerFactory.getLogger(StartupListener.class);

    static {
        InputStream input = null;//读取config.properties配置文件
        InputStream keysInputStream = null; // keys.properties
        try {
            input = StartupListener.class.getResourceAsStream("/config.properties");
            keysInputStream = StartupListener.class.getResourceAsStream("/keys.properties");
            logger.info("properties load " + (input == null ? "failed" : "success"));
            Properties properties = null;
            if (input != null){
                properties = new Properties();
                properties.load(input);
            }
            Properties keys = null;
            if(keysInputStream != null){
                keys = new Properties();
                keys.load(keysInputStream);
            }
            CommonConfig.init(properties); //公共配置
            ApiConfig.init(properties);//api配置
            KeysConfig.init(keys);
            MultiServlet.setApiManager(new ApiManager()); //m.api 小服务
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * 当Servlet 容器启动Web 应用时调用该方法。在调用完该方法之后，容器再对Filter 初始化，
     * 并且对那些在Web 应用启动时就需要被初始化的Servlet 进行初始化。
     * 将托管的jar包api消费者注册到注册中心
     */
    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        try {
        //Tomcat的WebappClassLoader加载指定目录的jar文件
        WebappClassLoader loader = (WebappClassLoader)getClass().getClassLoader();
        //被托管的api jar包目录
        File apiJarDirectory = new File(ApiConfig.getInstance().getApiJarPath());
        //dubbo 的 applicationConfig 应用信息配置(name:当前应用名称，用于注册中心计算应用间依赖关系)
        ApplicationConfig application = new ApplicationConfig();
        application.setName(ApiConfig.getInstance().getApplicationName());
        // 连接注册中心配置
        String[] addressArray = ApiConfig.getInstance().getZkAddress().split(" ");  //链接中心地址
        List<RegistryConfig> registryConfigList = new LinkedList<RegistryConfig>();  //注册中心配置列表
        //将注册中心地址，添加到注册中心配置列表
        for (String zkAddress : addressArray) {
            RegistryConfig registry = new RegistryConfig();
            registry.setAddress(zkAddress);
            registry.setProtocol("dubbo");
            registryConfigList.add(registry);
        }

        //业务服务
        if (apiJarDirectory.exists() && apiJarDirectory.isDirectory()) {

            File[] files = apiJarDirectory.listFiles(new FilenameFilter() {  //抓到目录中的jar包
                @Override
                public boolean accept(File file, String s) {
                    return s.endsWith(".jar");
                }
            });
            if (files != null) {
                //循环被托管的api jar包目录
                for (File f : files) {
                    JarFile jf = null; //当前jar包
                    try {
                        jf = new JarFile(f);
                        if ("dubbo".equals(jf.getManifest().getMainAttributes().getValue("Api-Dependency-Type"))) {  //接口必须依赖dubbo
                            String ns = jf.getManifest().getMainAttributes().getValue("Api-Export");
                            //对外的接口 eg:ren.yoki.user.api.LoginServiceHttpExport  ren.yoki.user.api.UserService
                            String[] names = ns.split(" ");
                            //tomcat 加载一个jar包
                            loader.addRepository(f.toURI().toURL().toString());
                            for (String name : names) {
                                if (name != null) {
                                    name = name.trim();
                                    if (name.length() > 0) {
                                        //反射出服务类
                                        Class<?> clazz = Class.forName(name);
                                        // 注意：ReferenceConfig为重对象，内部封装了与注册中心的连接，以及与服务提供方的连接
                                        // 引用远程服务 服务消费者引用服务配置
                                        ReferenceConfig reference = new ReferenceConfig(); // 此实例很重，封装了与注册中心的连接以及与提供者的连接，请自行缓存，否则可能造成内存和连接泄漏
                                        reference.setApplication(application);
                                        if (registryConfigList.size() > 0) {
                                            reference.setRegistries(registryConfigList);// 多个注册中心可以用setRegistries()
                                        }
                                        reference.setTimeout(CommonConfig.getInstance().getTimeout());
                                        reference.setInterface(clazz);
                                        reference.setCheck(false);
                                        if (ApiConfig.getInstance().getServiceVersion() != null && !ApiConfig.getInstance().getServiceVersion().isEmpty()) {
                                            reference.setVersion(ApiConfig.getInstance().getServiceVersion());
                                        }
                                            /*
                                            }
                                            */
                                        // 和本地bean一样使用xxxService
                                        reference.setRetries(0);
                                        Object service = null;
                                        // 和本地bean一样使用xxxService
                                        // 这个时候注册中心多出一个消费者
                                        service = reference.get(); // 注意：此代理对象内部封装了所有通讯细节，对象较重，请缓存复用
                                            /* } */
                                        if (service == null) {
                                            throw new RuntimeException("cannot find dubbo service for " + clazz.getName());
                                        }
                                        //通过apiManager注册生成的消费者远程连接服务（服务名，List<ApiMethodInfo>)
                                        MultiServlet.getApiManager().register(f.getName(), ApiManager.parseApi(clazz, service));
                                    }
                                }
                            }
                        }
                    } catch (Throwable t) {
                        logger.error("load api failed. " + f.getName(), t);
                    } finally {
                        if (jf != null) {
                            jf.close();
                        }
                    }
                }
            }
        }
    } catch (Throwable t) {
            t.printStackTrace();
        logger.error("load api failed.", t);
    }
    if (CompileConfig.isDebug) {
        DemoServlet.setApiMethodInfos(MultiServlet.getApiInfos());
    }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {

    }
}
