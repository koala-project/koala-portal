package com.koala.protal.common;

import com.alibaba.dubbo.common.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Properties;

public class KeysConfig extends HashMap<Long,String> {

    private static final Logger logger                 = LoggerFactory.getLogger(KeysConfig.class);
    private static KeysConfig instance;

    private KeysConfig() {
    }

    public static void init(Properties prop) {
        synchronized (ApiConfig.class) {
            if (instance == null) {
                instance = new KeysConfig();
            }
            if (prop == null) {
                throw new RuntimeException("api config init failed.");
            } else {
                for(String property : prop.stringPropertyNames()){
                    if(StringUtils.isNotEmpty(property)) {
                        instance.put(Long.parseLong(property), prop.getProperty(property));
                    }
                }
            }
        }
    }

    public static KeysConfig getKeys(){
        if (instance == null) {
            throw new RuntimeException("keys config not init.");
        }
        return instance;
    }
}
