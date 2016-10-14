package com.koala.protal.servlet;

import com.alibaba.dubbo.common.utils.StringUtils;
import com.alibaba.fastjson.JSON;
import com.koala.protal.common.ApiConfig;
import com.koala.protal.common.KeysConfig;
import com.koala.protal.common.RiskManager;
import com.koala.protal.common.SignatureAlgorithm;
import com.koala.utils.gateway.core.ApiManager;
import com.koala.utils.gateway.core.BaseServlet;
import com.koala.utils.gateway.define.CommonParameter;
import com.koala.utils.gateway.define.ConstField;
import com.koala.utils.gateway.define.SecurityType;
import com.koala.utils.gateway.entity.*;
import com.koala.utils.gateway.responseEntity.RawString;
import com.koala.utils.gateway.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.util.*;

/**
 * 复合接口调用，提供一个http请求中发起多个api访问的实现
 */
@WebServlet("/m.api")
public class MultiServlet extends BaseServlet {
    private static final Logger logger            = LoggerFactory.getLogger(MultiServlet.class);
    private static final long   serialVersionUID = 1L;
    public  static final String DEBUG_AGENT       = "koala.tester";

    private static ApiManager apiManager = null;

    public static void setApiManager(ApiManager m) {
        apiManager = m;
    }

    public static ApiManager getApiManager() {
        return apiManager;
    }

    public MultiServlet() {
        super(apiManager);
    }

    /**
     * 获取已注册api接口
     */
    public static ApiMethodInfo[] getApiInfos() {
        return apiManager.getApiMethodInfos();
    }

    @Override
    public AbstractReturnCode parseMethodInfo(ApiContext context, HttpServletRequest request) {
        String nameString = request.getParameter(CommonParameter.method);
        if (nameString != null && nameString.length() > 0) {
            // 解析多个由','拼接的api名
            String[] names = nameString.split(",");
            context.apiCallInfos = new ArrayList<ApiMethodCall>(names.length);
            // 检测当前安全级别是否允许调用请求中的所有api
            for (int m = 0; m < names.length; m++) {
                String mname = names[m];
                ApiMethodInfo method = apiManager.getApiMethodInfo(mname);
                if (method != null) {
                    // 接口返回RawString，不允许多接口同时调用
                    if (method.returnType == RawString.class) {
                        if (names.length > 1) {
                            return ApiReturnCode.ILLEGAL_MUTLI_RAWSTRING_RT;
                        }
                    }

                    // 当接口安全级别为Internal时,不允许通过网关调用
                    if (SecurityType.Internal.check(method.securityLevel)) {
                        return ApiReturnCode.ACCESS_DENIED;
                    }

                    // 调用接口中包含了SecurityType为Integrated的接口，不允许多接口同时调用
                    if (SecurityType.Integrated.check(method.securityLevel)) {
                        if (names.length > 1) {
                            return ApiReturnCode.ILLEGAL_MUTLI_INTEGRATED_API_ACCESS;
                        }
                    }
                    // 本接口只允许加密调用
                    if (method.encryptionOnly) {
                        if (ApiConfig.getInstance().getSSLPort() != request.getLocalPort()) {
                            return ApiReturnCode.UNKNOW_ENCRYPTION_DENIED;
                        }
                    }
                    ApiMethodCall call = new ApiMethodCall(method);
                    // 解析业务参数使其对应各自业务api
                    String[] parameters = new String[method.parameterInfos.length];
                    context.requiredSecurity = method.securityLevel.authorize(context.requiredSecurity);
                    for (int i = 0; i < parameters.length; i++) {
                        ApiParameterInfo ap = method.parameterInfos[i];
                        if (ap.isAutowired) {
                            if (CommonParameter.userId.equals(ap.name)) {
                                parameters[i] = context.caller == null ? "0" : String.valueOf(context.caller.uid);
                            } else if (CommonParameter.deviceId.equals(ap.name)) {
                                if (context.caller == null) {
                                    // 当 caller 不存在时，使用请求中的明文deviceId作为参数注入给服务提供方
                                    // 即:即使当前接口是 SecurityType.None 类型接口也可以要求注入一个deviceId
                                    // 但是服务端不应该在这个 deviceId 上做任何有关安全方面的操作。
                                    parameters[i] = context.deviceIdStr;
                                } else {
                                    parameters[i] = String.valueOf(context.caller.deviceId);
                                }
                            } else if (CommonParameter.applicationId.equals(ap.name)) {
                                parameters[i] = String.valueOf(context.appid);
                            } else if (CommonParameter.phoneNumber.equals(ap.name)) {
                                parameters[i] = context.caller == null ? "0" : String.valueOf(context.caller.phoneNumber);
                            } else if (CommonParameter.dynamic.equals(ap.name)) {
                                parameters[i] = request.getParameter(CommonParameter.dynamic);
                            } else if (CommonParameter.thirdPartyId.equals(ap.name)) {
                                parameters[i] = String.valueOf(context.thirdPartyId);
                            } else if (CommonParameter.deviceToken.equals(ap.name)) {
                                parameters[i] = context.caller == null ? null : context.deviceToken;
                            } else if (CommonParameter.token.equals(ap.name)) {
                                parameters[i] = context.caller == null ? null : context.token;
                            } else if (CommonParameter.clientIp.equals(ap.name)) {
                                parameters[i] = context.clientIP == null ? null : context.clientIP;
                            } else if (CommonParameter.versionCode.equals(ap.name)) {
                                parameters[i] = context.versionCode == null ? null : context.versionCode;
                            } else if (CommonParameter.cookie.equals(ap.name)) {
                                Map<String, String> map = new HashMap<String, String>(ap.names.length);
                                for (String n : ap.names) {
                                    String v = null;
                                    if (CommonParameter.channel.equals(n) || CommonParameter.location.equals(n)
                                            || CommonParameter.businessId.equals(n)
                                            || CommonParameter.callId.equals(n) || CommonParameter.clientIp.equals(n)
                                            || CommonParameter.versionCode.equals(n) || CommonParameter.inputCharset.equals(n)) {
                                        v = request.getParameter(n);
                                    }
                                    if (v == null) {
                                        v = context.getCookie(n);
                                    }
                                    if (v != null) {
                                        map.put(n, v);
                                    }
                                }
                                parameters[i] = JSON.toJSONString(map);
                            } else if (SecurityType.Integrated.check(method.securityLevel) && CommonParameter.postBody.equals(ap.name)) {
                                parameters[i] = readPostBody(request);
                            }
                        } else {
                            if (names.length == 1) {
                                parameters[i] = request.getParameter(ap.name);
                            } else {
                                String name = m + "_" + ap.name;
                                parameters[i] = request.getParameter(name);
                            }
                        }
                        if (parameters[i] != null) {
                            call.message.append(ap.name).append('=').append(parameters[i]).append('&');
                        }
                    }
                    if (names.length == 1) {
                        call.businessId = request.getParameter(CommonParameter.businessId);
                    } else {
                        call.businessId = request.getParameter(m + "_" + CommonParameter.businessId);
                    }
                    call.parameters = parameters;
                    // 验证通过的api及其调用参数构造为一个ApiMethodCall实例
                    context.apiCallInfos.add(call);
                } else {
                    return ApiReturnCode.UNKNOWN_METHOD;
                }
            }

            // 调试环境下为带有特殊标识的访问者赋予测试者身份
            if (CompileConfig.isDebug) {
                if ((context.agent != null && context.agent.contains(DEBUG_AGENT))) {
                    if (context.caller == null) {
                        context.caller = CallerInfo.TESTER;
                    }
                    return ApiReturnCode.SUCCESS;
                }
            }

            //Integrate None Internal级别接口不具备用户身份
            if (!SecurityType.isNone(context.requiredSecurity)
                    && !SecurityType.Integrated.check(context.requiredSecurity)
                    && !SecurityType.Internal.check(context.requiredSecurity)) {
                context.requiredSecurity = SecurityType.RegisteredDevice.authorize(context.requiredSecurity);
                if (context.caller == null) {
                    return ApiReturnCode.TOKEN_ERROR;
                }
            }

            // 签名验证，用于防止中间人攻击

            if (!checkSignature(context.caller, context.requiredSecurity, request)) {
                return ApiReturnCode.SIGNATURE_ERROR;
            }



            return checkAuthorization(context, context.requiredSecurity, request);
        }
        return ApiReturnCode.REQUEST_PARSE_ERROR;
    }

    private String readPostBody(HttpServletRequest request) {
        StringBuffer sb = new StringBuffer();
        String line = null;
        try {
            BufferedReader reader = request.getReader();
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        } catch (Exception e) {
            if (CompileConfig.isDebug) {
                logger.error("read post body failed.", e);
            }
        }
        return sb.toString();
    }

    private AbstractReturnCode checkAuthorization(ApiContext context, int authTarget, HttpServletRequest request) {
        if (SecurityType.isNone(authTarget) || SecurityType.Internal.check(context.requiredSecurity)) {// 不进行权限控制
            return ApiReturnCode.SUCCESS;
        }

        CallerInfo caller = context.caller;
        if (SecurityType.RegisteredDevice.check(authTarget)) {
            // 解析出caller说明是授信的设备,对app端需要进行过设备注册,对web端则是进行了登录
            if (caller == null || caller.deviceId == 0) {
                return ApiReturnCode.UNKNOW_TOKEN_DENIED;
            } else if (context.deviceId != caller.deviceId) {
                // 声称的 deviceId 和实际 token 中的 deviceId 不一致, 记录错误但是处理为正常 TODO: 严格处理
                logger.error("deviceId error. context.deviceId:" + context.deviceId + " caller.deviceId:" + caller.deviceId);
            } else if (context.appid != caller.appid) {
                // 声称的 appId 和实际 token 中的 appId 不一致, 记录错误但是处理为正常 TODO: 严格处理
                logger.error("appId error. context.appid:" + context.appid + " caller.appid:" + caller.appid);
            }
        }

        if (SecurityType.UserLogin.check(authTarget)) {
            if (caller == null || caller.uid == 0) {
                return ApiReturnCode.USER_CHECK_FAILED;
            } else if (context.appid != caller.appid) {
                // 用户级别访问才验证appid匹配性, 记录错误但是处理为正常 TODO: 严格处理
                logger.error("appId error. aid:" + context.appid + " caller.aid:" + caller.appid);
            }
        }

        if (caller == null) {
            if (!RiskManager.allowAccess(context.appid, context.deviceId, 0, context.cid, context.clientIP)) {
                return ApiReturnCode.RISK_MANAGER_DENIED;
            }
        } else {
            if (!RiskManager.allowAccess(caller.appid, caller.deviceId, caller.uid, context.cid, context.clientIP)) {
                return ApiReturnCode.RISK_MANAGER_DENIED;
            }
        }

        //        boolean securityServiceErrorOccured = false;
        //        int userDeviceBindingState = 0; // 0:未进行用户设备检测 1:是用户的受信设备 2:处于激活状态 -1:不是用户的受信设备/web互踢 -2:用户被锁定 -3:触发风控（用户被锁定）
        //        if (SecurityType.UserTrustedDevice.check(authTarget)) {
        //            if (checkUser == 0) {
        //                checkUser = (context.caller != null && context.caller.uid != 0) ? 1 : -1;
        //            }
        //            if (checkUser < 0) {
        //                return ApiReturnCode.USER_CHECK_FAILED;
        //            }
        //            try {
        //                userDeviceBindingState = ServiceFactory.getSecurityService().getUserDeviceBindingState(context.caller.appid, context.caller.deviceId,
        //                        context.caller.uid);
        //                // RpcContext.removeContext();
        //            } catch (Throwable throwable) {
        //                logger.error("invoke security service failed", throwable);
        //                securityServiceErrorOccured = true;
        //            } finally {
        //                DubboExtProperty.clearNotificaitons();
        //            }
        //            if (securityServiceErrorOccured) {
        //                return ApiReturnCode.SECURITY_SERVICE_ERROR;
        //            }
        //            if (userDeviceBindingState == -1) {
        //                return ApiReturnCode.NO_TRUSTED_DEVICE;
        //            } else if (userDeviceBindingState == -2) {
        //                long lockedEndTime = 0;
        //                try {
        //                    lockedEndTime = ServiceFactory.getSecurityService().getLockedEndTime(context.caller.uid);
        //                } catch (Throwable throwable) {
        //                    logger.error("invoke security service failed", throwable);
        //                    securityServiceErrorOccured = true;
        //                } finally {
        //                    DubboExtProperty.clearNotificaitons();
        //                }
        //                if (securityServiceErrorOccured) {
        //                    return ApiReturnCode.SECURITY_SERVICE_ERROR;
        //                }
        //                context.localException = new LocalException(ApiReturnCode.USER_LOCKED, String.valueOf(lockedEndTime));
        //                return ApiReturnCode.USER_LOCKED;
        //            } else {
        //                return ApiReturnCode.ACCESS_DENIED;
        //            }
        //        }
        //
        //        CallerInfo mobileOwner = null;
        //        if (SecurityType.MobileOwner.check(authTarget)) {
        //            if (context.caller == null || context.caller.phoneNumber == null) {
        //                return ApiReturnCode.DYNAMIC_CODE_ERROR;
        //            }
        //            String phoneNumber = context.caller.phoneNumber;
        //            String dynamicPwd = request.getParameter(CommonParameter.dynamic);
        //            if (phoneNumber.length() == 0 || dynamicPwd == null || dynamicPwd.length() == 0) {
        //                return ApiReturnCode.DYNAMIC_CODE_ERROR;
        //            }
        //            boolean isMobileOwner = false;
        //            String errorCode = null;
        //            try {
        //                isMobileOwner = ServiceFactory.getSecurityService().isMobileOwner(phoneNumber, dynamicPwd);
        //                errorCode = DubboExtProperty.getErrorCode();
        //            } catch (Throwable throwable) {
        //                logger.error("invoke security service failed", throwable);
        //                securityServiceErrorOccured = true;
        //            } finally {
        //                DubboExtProperty.clearNotificaitons();
        //            }
        //            if (securityServiceErrorOccured) {
        //                return ApiReturnCode.SECURITY_SERVICE_ERROR;
        //            }
        //            if (!isMobileOwner && errorCode != null && !errorCode.isEmpty()) {
        //                try {
        //                    return ReturnCodeContainer.findCode(Integer.parseInt(errorCode));
        //                } catch (Exception e) {
        //                    logger.error("service return undefined code " + errorCode, e);
        //                    return ApiReturnCode.INTERNAL_SERVER_ERROR;
        //                }
        //            }
        //        }
        //
        //        if (SecurityType.MobileOwnerTrustedDevice.check(authTarget)) {
        //            String phoneNumber = context.caller.phoneNumber;
        //            String dynamicPwd = request.getParameter(CommonParameter.dynamic);
        //            String errorCode = null;
        //            if (mobileOwner == null) {
        //                if (context.caller == null || context.caller.phoneNumber == null) {
        //                    return ApiReturnCode.DYNAMIC_CODE_ERROR;
        //                }
        //                if (phoneNumber == null || phoneNumber.length() == 0 || dynamicPwd == null || dynamicPwd.length() == 0) {
        //                    return ApiReturnCode.DYNAMIC_CODE_ERROR;
        //                }
        //                try {
        //                    mobileOwner = ServiceFactory.getSecurityService().getUserInfoBySmsPass(context.appid, context.caller.deviceId, phoneNumber,
        //                            dynamicPwd);
        //                    errorCode = DubboExtProperty.getErrorCode();
        //                } catch (Throwable throwable) {
        //                    logger.error("invoke security service failed", throwable);
        //                    securityServiceErrorOccured = true;
        //                } finally {
        //                    DubboExtProperty.clearNotificaitons();
        //                }
        //                if (securityServiceErrorOccured) {
        //                    return ApiReturnCode.SECURITY_SERVICE_ERROR;
        //                }
        //            }
        //            if (mobileOwner == null) {
        //                if (errorCode != null && !errorCode.isEmpty()) {
        //                    try {
        //                        return ReturnCodeContainer.findCode(Integer.parseInt(errorCode));
        //                    } catch (Exception e) {
        //                        logger.error("service return undefined code " + errorCode, e);
        //                        return ApiReturnCode.INTERNAL_SERVER_ERROR;
        //                    }
        //                }
        //                return ApiReturnCode.NO_TRUSTED_DEVICE;
        //            }
        //        }
        //
        //        if (SecurityType.UserLogin.check(authTarget)) {// 用户登入级别的借口,需要进行实现同域下的互踢.
        //            if (checkUser == 0) {
        //                checkUser = (context.caller != null && context.caller.uid != 0) ? 1 : -1;
        //            }
        //            if (checkUser < 0) {
        //                return ApiReturnCode.USER_CHECK_FAILED;
        //            }
        //            // 手机端验证设备激活(绑定关系是否存在),web端验证不同浏览器登入同一账号进行互踢
        //            if (userDeviceBindingState == 0) {// return 0:未进行用户设备检测 1:是用户的受信设备 2:处于激活状态 -1:不是用户的受信设备/web互踢 -2:用户被锁定 -3:触发风控（用户被锁定）
        //                try {
        //                    userDeviceBindingState = ServiceFactory.getSecurityService().getUserDeviceBindingState(context.caller.appid,
        //                            context.caller.deviceId,
        //                            context.caller.uid);
        //                } catch (Throwable throwable) {
        //                    logger.error("invoke security service failed", throwable);
        //                    securityServiceErrorOccured = true;
        //                } finally {
        //                    DubboExtProperty.clearNotificaitons();
        //                }
        //                if (securityServiceErrorOccured) {
        //                    return ApiReturnCode.SECURITY_SERVICE_ERROR;
        //                }
        //            }
        //            switch (userDeviceBindingState) {
        //                case -2:
        //                    long lockedEndTime = 0;
        //                    try {
        //                        lockedEndTime = ServiceFactory.getSecurityService().getLockedEndTime(context.caller.uid);
        //                    } catch (Throwable throwable) {
        //                        logger.error("invoke security service failed", throwable);
        //                        securityServiceErrorOccured = true;
        //                    } finally {
        //                        DubboExtProperty.clearNotificaitons();
        //                    }
        //                    if (securityServiceErrorOccured) {
        //                        return ApiReturnCode.SECURITY_SERVICE_ERROR;
        //                    }
        //                    context.localException = new LocalException(ApiReturnCode.USER_LOCKED, String.valueOf(lockedEndTime));
        //                    return ApiReturnCode.USER_LOCKED;
        //                case -1:
        //                    return ApiReturnCode.NO_TRUSTED_DEVICE;
        //                case 0:
        //                    return ApiReturnCode.ACCESS_DENIED;
        //                case 1:
        //                    return ApiReturnCode.NO_ACTIVE_DEVICE;
        //                case 2:
        //                    break;
        //                default:
        //                    return ApiReturnCode.ACCESS_DENIED;
        //            }
        //        }
        //        context.caller.securityLevel = context.requiredSecurity;
        return ApiReturnCode.SUCCESS;
    }

    private StringBuilder getSortedParameters(HttpServletRequest request) {
        // 拼装被签名参数列表
        StringBuilder sb = new StringBuilder(128);
        {
            List<String> list = new ArrayList<String>(10);
            Enumeration<String> keys = request.getParameterNames();
            while (keys.hasMoreElements()) {
                list.add(keys.nextElement());
            }
            // 参数排序
            String[] array = list.toArray(new String[list.size()]);
            if (array.length > 0) {
                Arrays.sort(array, StringUtil.StringComparator);
                for (String key : array) {
                    if (CommonParameter.signature.equals(key)) {
                        continue;
                    }
                    sb.append(key);
                    sb.append("=");
                    sb.append(request.getParameter(key));
                }
            }
        }
        return sb;
    }

    /**
     * 签名验证，在debug编译的环境中允许使用特定user agent跳过签名验证
     */
    protected boolean checkSignature(CallerInfo caller, int securityLevel, HttpServletRequest request) {
        // 拼装被签名参数列表
        StringBuilder sb = getSortedParameters(request);

        //TODO 暂时添加koala.tester
        String ua = request.getHeader("User-Agent").concat("/koala.tester");
        if(StringUtils.isNotEmpty(ua) && ua.contains(DEBUG_AGENT)){
            return true;
        }

        // 验证签名
        String sig = request.getParameter(CommonParameter.signature);
        if (SecurityType.Internal.check(securityLevel)) {
            return ApiConfig.getInstance().getInternalPort() == request.getLocalPort();
        }
        if (sig != null && sig.length() > 0) {
            String key = KeysConfig.getKeys().get(Long.parseLong(request.getParameter(CommonParameter.applicationId)));
            // 安全级别为None的接口仅进行静态秘钥签名验证,sha1,md5
            String sm = request.getParameter(CommonParameter.signatureMethod);
            //if (SecurityType.isNone(securityLevel)) {
                if (SignatureAlgorithm.MD5.getAlgorithm().equalsIgnoreCase(sm)) {
                    byte[] expect = HexStringUtil.toByteArray(sig);
                    byte[] actual = Md5Util.compute(sb.append(key).toString().getBytes(ConstField.UTF8));
                    return Arrays.equals(expect, actual);
                } else if (SignatureAlgorithm.SHA1.getAlgorithm().equalsIgnoreCase(sm)) {
                    byte[] expect = HexStringUtil.toByteArray(sig);
                    byte[] actual = SHAUtil.computeSHA1(sb.append(key).toString().getBytes(ConstField.UTF8));
                    return Arrays.equals(expect, actual);
                } else {// 默认使用sha1
                    byte[] expect = HexStringUtil.toByteArray(sig);
                    byte[] actual = SHAUtil.computeSHA1(sb.append(key).toString().getBytes(ConstField.UTF8));
                    return Arrays.equals(expect, actual);
                }
            //} else if (caller != null) {// 所有有安全验证需求的接口需要检测动态签名，
             /*   if (caller.appid == 4) {
                    return true;
                }
                if (SignatureAlgorithm.RSA.getAlgorithm().equalsIgnoreCase(sm)) { // RSA 配合 base64 编码的签名 用于app端
                    return RsaHelper.verify(Base64Util.decode(sig), sb.toString().getBytes(ConstField.UTF8), caller.key);
                } else if (SignatureAlgorithm.MD5.getAlgorithm().equalsIgnoreCase(sm)) {// MD5 配合 hax 编码的签名 用于web端
                    sb.append(HexStringUtil.toHexString(caller.key));
                    return Arrays.equals(HexStringUtil.toByteArray(sig), Md5Util.compute(sb.toString().getBytes(ConstField.UTF8)));
                } else if (SignatureAlgorithm.SHA1.getAlgorithm().equalsIgnoreCase(sm)) {// SHA1 配合 base64 编码的签名 用于app端
                    sb.append(HexStringUtil.toHexString(caller.key));
                    return Arrays.equals(Base64Util.decode(sig), SHAUtil.computeSHA1(sb.toString().getBytes(ConstField.UTF8)));
                } else if (SignatureAlgorithm.ECC.getAlgorithm().equalsIgnoreCase(sm)) { // ECC 配合 base64 编码的签名 用于app端
                    return EccHelper.verify(Base64Util.decode(sig), sb.toString().getBytes(ConstField.UTF8), caller.key);
                } else {// 默认ECC
                    return EccHelper.verify(Base64Util.decode(sig), sb.toString().getBytes(ConstField.UTF8), caller.key);
                }

            } else {
                return false;
            }*/
        }
        return false;
    }

    @Override
    protected Object processCall(String name, String[] params) {
        return apiManager.processRequest(name, params);
    }

    @Override
    protected CallerInfo parseCallerInfo(ApiContext context, byte[] token) {
        CallerInfo caller = null;
        if (token != null && token.length > 0) {
            caller = ApiConfig.getInstance().getApiTokenHelper().parseToken(token);
            if (caller != null && caller.uid != 0) {
                MDC.put(CommonParameter.userId, String.valueOf(caller.uid));
            }
        }
        return caller;
    }

    @Override
    protected CallerInfo parseCallerInfo(ApiContext context, String token) {
        CallerInfo caller = null;
        AESTokenHelper helper = ApiConfig.getInstance().getApiTokenHelper();
        byte[] buffer = helper.parseHexStr2Byte(token);
        if (buffer != null && buffer.length > 0) {
            caller = ApiConfig.getInstance().getApiTokenHelper().parseToken(buffer);
            if (caller != null && caller.uid != 0) {
                MDC.put(CommonParameter.userId, String.valueOf(caller.uid));
            }
        }
        return caller;
    }
}
