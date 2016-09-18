package com.koala.protal.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RiskManager {
    private static final Logger logger = LoggerFactory.getLogger(RiskManager.class);

    private static RiskManager getInstance() {
        return RiskManagerHolder.manager;
    }

    public static boolean allowAccess(int appId, long deviceId, long userId, String callId, String clientIp) {
        RiskManager manager = getInstance();
        if (manager != null) {
            return manager.allow(appId, deviceId, userId, callId, clientIp);
        }
        return true;
    }

    private RiskManager() {

    }

    public boolean allow(int appId, long deviceId, long userId, String callId, String clientIp) {
        try {

        } catch (Exception e) {
            RiskManagerHolder.manager = null;
            logger.error("risk manager load failed!", e);
        }
        return true;
    }

    public static class RiskManagerHolder {
        public static RiskManager manager;

        static {
            try {
                manager = null;

                manager = new RiskManager();

            } catch (Exception e) {
                manager = null;
                logger.error("risk manager load failed!", e);
            }
        }
    }
}
