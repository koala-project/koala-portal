package com.koala.protal.common;

import com.koala.utils.gateway.entity.CompileConfig;
import com.koala.utils.gateway.util.AESTokenHelper;
import com.koala.utils.gateway.util.AesHelper;
import com.koala.utils.gateway.util.Base64Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

/**
 * @Author Liuyf
 * @Date 2016-09-14
 * @Time 15:03
 * @Description
 */
public class ApiConfig {
    public static final Logger logger = LoggerFactory.getLogger(ApiConfig.class);
    private static final String DEFAULT_SEVICE_VERSION = "default";
    private ThreadLocal<AESTokenHelper> apiTokenHelper = new ThreadLocal<AESTokenHelper>();
    public static ApiConfig instance;

    public ApiConfig() {}

    private String apiJarPath = null;
    private String zkAddress = null;
    private String serviceVersion = null;
    private int sslPort = -1;
    private int internalPort = -1;
    /**
     * 用于加密服务端token
     */
    private String apiTokenAes = null;

    /**
     * apigw在注册中心的名字
     */
    private String applicationName = "apigw";


    public static void init(Properties prop){
        synchronized (ApiConfig.class){
            if (instance == null) instance = new ApiConfig();
            if (prop == null) {
                throw new RuntimeException("api config init failed.");
            } else {
                instance.setApiJarPath(prop.getProperty("com.koala.portal.gateway.jarPath"));
                instance.setZkAddress(prop.getProperty("dubbo.registry.url"));
                instance.setServiceVersion(prop.getProperty("dubbo.reference.version"));
                instance.setSSLPort(prop.getProperty("com.koala.portal.gateway.sslPort"));
                instance.setInternalPort(prop.getProperty("com.koala.portal.gateway.internalPort"));
                instance.setApiTokenAes(prop.getProperty("com.koala.portal.gateway.tokenAes"));
            }
        }
    }

    public static ApiConfig getInstance() {
        if (instance == null)throw new RuntimeException("ApiConfig not init.");
        return instance;
    }


    public String getApiJarPath() {
        return apiJarPath;
    }

    public void setApiJarPath(String apiJarPath) {
        this.apiJarPath = apiJarPath;
        if (CompileConfig.isDebug)
            logger.info("[ApiConfig.init]com.ulife.portal.gateway.jarPath:{}", this.apiJarPath);
    }

    public String getZkAddress() {
        return zkAddress;
    }

    public void setZkAddress(String zkAddress) {
        if (zkAddress == null || zkAddress.isEmpty()) {
            throw new RuntimeException("can not find zk address config");
        }
        this.zkAddress = zkAddress;
        if (CompileConfig.isDebug)
            logger.info("[ApiConfig.init]dubbo.registry.url:{}", this.zkAddress);
    }

    public String getServiceVersion() {
        return serviceVersion;
    }

    public void setServiceVersion(String serviceVersion) {
        if (serviceVersion != null && !serviceVersion.isEmpty()) {
            if (!serviceVersion.trim().isEmpty() && !serviceVersion.equalsIgnoreCase(DEFAULT_SEVICE_VERSION)) {
                this.serviceVersion = serviceVersion;
            } else {
                this.serviceVersion = "";
            }
        } else {
            throw new RuntimeException("can not find service version config");
        }
        if (CompileConfig.isDebug)
            logger.info("[ApiConfig.init]dubbo.reference.version:{}", this.serviceVersion);
    }

    public String getApplicationName() {
        return applicationName;
    }

    private void setSSLPort(String sslPort) {
        if (sslPort != null && !sslPort.isEmpty() && !sslPort.trim().isEmpty()) {
            this.sslPort = Integer.parseInt(sslPort);
        }
        if (CompileConfig.isDebug)
            logger.info("[ApiConfig.init]com.koala.portal.gateway.sslPort:{}", sslPort);
    }

    public int getSSLPort() {
        return sslPort;
    }

    private void setInternalPort(String internalPort) {
        if (internalPort != null && !internalPort.isEmpty() && !internalPort.trim().isEmpty()) {
            this.internalPort = Integer.parseInt(internalPort);
        }
        if (CompileConfig.isDebug)
            logger.info("[ApiConfig.init]com.koala.portal.gateway.internalPort:{}", internalPort);
    }

    public int getInternalPort() {
        return internalPort;
    }

    private void setApiTokenAes(String apiTokenAes) {
        this.apiTokenAes = apiTokenAes;
        if (CompileConfig.isDebug)
            logger.info("[ApiConfig.init]com.koala.portal.gateway.tokenAes:{}", apiTokenAes);
    }

    public AESTokenHelper getApiTokenHelper() {
        AESTokenHelper helper = apiTokenHelper.get();
        if (helper == null) {
            helper = new AESTokenHelper(new AesHelper(Base64Util.decode(apiTokenAes), null));
            apiTokenHelper.set(helper);
        }
        return helper;
    }

}
