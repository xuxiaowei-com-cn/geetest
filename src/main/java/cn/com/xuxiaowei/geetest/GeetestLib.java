package cn.com.xuxiaowei.geetest;

import com.alibaba.fastjson.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 极验 Java SDK
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class GeetestLib {

    private final String JSON_FORMAT = "1";

    /**
     * 成功响应
     */
    private final String SUCCESS = "success";

    /**
     * 极验验证二次验证表单数据 chllenge
     */
    private static final String GEETEST_CHALLENGE = "geetest_challenge";

    /**
     * 极验验证二次验证表单数据 validate
     */
    private static final String GEETEST_VALIDATE = "geetest_validate";

    /**
     * 极验验证二次验证表单数据 seccode
     */
    private static final String GEETEST_SECCODE = "geetest_seccode";

    /**
     * 极验验证API服务状态Session Key
     */
    private final String GT_SERVER_STATUS_SESSION_KEY = "gt_server_status";

    /**
     * 放入 Session 中的用户标识
     */
    private final String GEETEST_USER_ID = "geetest_user_id";

    /**
     * 公钥
     */
    private final String captchaId;

    /**
     * 私钥
     */
    private final String privateKey;

    /**
     * 是否开启新的 failback
     */
    private final boolean newFailback;

    /**
     * 错误响应
     */
    private final String FAIL = "fail";

    /**
     * 响应 JSON
     */
    private JSONObject responseJson;

    /**
     * 调试开关，是否输出调试日志
     */
    private final boolean debug;

    /**
     * 默认构造器
     * <p>
     * 默认调试开关
     *
     * @param captchaId   公钥
     * @param privateKey  私钥
     * @param newFailback 是否开启新的 failback
     */
    public GeetestLib(String captchaId, String privateKey, boolean newFailback) {
        this.captchaId = captchaId;
        this.privateKey = privateKey;
        this.newFailback = newFailback;
        this.debug = true;
    }

    /**
     * 全参构造器
     * <p>
     * 可选调试状态
     *
     * @param captchaId   公钥
     * @param privateKey  私钥
     * @param newFailback 是否开启新的 failback
     * @param debug       调试开关，是否输出调试日志
     */
    public GeetestLib(String captchaId, String privateKey, boolean newFailback, boolean debug) {
        this.captchaId = captchaId;
        this.privateKey = privateKey;
        this.newFailback = newFailback;
        this.debug = debug;
    }

    /**
     * 获取极验
     *
     * @param request      请求
     * @param geetestParam 极验参数
     * @return 返回极验
     */
    public JSONObject geetest(HttpServletRequest request, GeetestParam geetestParam) {

        // 进行验证预处理
        int gtServerStatus = preProcess(geetestParam);

        HttpSession session = request.getSession();

        // 将服务器状态设置到 session 中
        session.setAttribute(GT_SERVER_STATUS_SESSION_KEY, gtServerStatus);

        // 将 userid 设置到 session 中
        session.setAttribute(GEETEST_USER_ID, geetestParam.getUserId());

        return responseJson;
    }

    /**
     * 极验验证，boolean
     *
     * @param request 请求
     * @param param   参数
     * @return 返回极验验证结果，boolean
     * @throws UnsupportedEncodingException 转 URLEncoder 异常
     */
    public boolean verify(HttpServletRequest request, VerifyParam param) throws UnsupportedEncodingException {
        JSONObject jsonObject = verifyJson(request, param);
        Object status = jsonObject.get("status");
        return SUCCESS.equals(status);
    }

    /**
     * 极验验证，JSONObject
     *
     * @param param   参数
     * @param request 请求
     * @return 返回极验验证结果
     * @throws UnsupportedEncodingException 转 URLEncoder 异常
     */
    public JSONObject verifyJson(HttpServletRequest request, VerifyParam param) throws UnsupportedEncodingException {

        String challenge = request.getParameter(GeetestLib.GEETEST_CHALLENGE);
        String validate = request.getParameter(GeetestLib.GEETEST_VALIDATE);
        String seccode = request.getParameter(GeetestLib.GEETEST_SECCODE);

        HttpSession session = request.getSession();

        //从session中获取gt-server状态
        int gtServerStatusCode = (Integer) session.getAttribute(GT_SERVER_STATUS_SESSION_KEY);

        //从 session 中获取 userid
        String userid = (String) session.getAttribute(GEETEST_USER_ID);

        param.setUserId(userid);

        int gtResult;

        if (gtServerStatusCode == 1) {
            //gt-server正常，向gt-server进行二次验证
            gtResult = enhencedValidateRequest(challenge, validate, seccode, param);
        } else {
            // gt-server非正常情况下，进行failback模式验证
            debug("failback：使用您自己的服务器验证码验证");
            gtResult = failbackValidateRequest(challenge, validate, seccode);
            debug(gtResult + "");
        }

        JSONObject data = new JSONObject();
        data.put("version", "4.0");

        if (gtResult == 1) {
            // 验证成功
            data.put("status", SUCCESS);
            return data;
        } else {
            // 验证失败
            data.put("status", FAIL);
            return data;
        }
    }

    /**
     * 预处理失败后的返回格式串
     *
     * @return 返回响应失败后的 JSONObject
     */
    private JSONObject getFailPreProcessRes() {

        long rnd1 = Math.round(Math.random() * 100);
        long rnd2 = Math.round(Math.random() * 100);
        String md5Str1 = md5Encode(rnd1 + "");
        String md5Str2 = md5Encode(rnd2 + "");
        assert md5Str2 != null;
        String challenge = md5Str1 + md5Str2.substring(0, 2);

        JSONObject jsonObject = new JSONObject();

        jsonObject.put("success", 0);
        jsonObject.put("gt", captchaId);
        jsonObject.put("challenge", challenge);
        jsonObject.put("new_captcha", newFailback);

        return jsonObject;
    }

    /**
     * 预处理成功后的标准串
     *
     * @param challenge challenge
     * @return 返回响应成功后的 JSONObject
     */
    private JSONObject getSuccessPreProcessRes(String challenge) {

        debug("challenge:" + challenge);

        JSONObject jsonObject = new JSONObject();

        jsonObject.put("success", 1);
        jsonObject.put("gt", captchaId);
        jsonObject.put("challenge", challenge);

        return jsonObject;
    }

    /**
     * 验证初始化预处理
     *
     * @return 1表示初始化成功，0表示初始化失败
     */
    private int preProcess(GeetestParam data) {
        if (registerChallenge(data) != 1) {
            responseJson = getFailPreProcessRes();
            return 0;
        }
        return 1;
    }

    /**
     * 用 captchaId 进行注册，更新 challenge
     *
     * @param data 包含信息：
     *             user_id：用户标识
     *             client_type：web：电脑上的浏览器，h5：手机上的浏览器，包括移动应用内完全内置的web_view，native：通过原生SDK植入APP应用的方式
     *             ip_address：IP
     * @return 1 表示注册成功，0 表示注册失败
     */
    private int registerChallenge(GeetestParam data) {

        try {
            String userId = URLEncoder.encode(data.getUserId(), "utf-8");
            String clientType = URLEncoder.encode(data.getClientType().type, "utf-8");
            String ipAddress = URLEncoder.encode(data.getIpAddress(), "utf-8");

            StringBuilder stringBuilder = new StringBuilder("http://api.geetest.com/register.php?");

            stringBuilder.append("gt=").append(captchaId);
            stringBuilder.append("&json_format=").append(JSON_FORMAT);

            // 参数处理
            param(userId, clientType, ipAddress, stringBuilder);

            String url = stringBuilder.toString();

            debug("GET_URL:" + url);
            String resultStr = readContentFromGet(url);
            if (FAIL.equals(resultStr)) {
                debug("用 captchaId 进行注册，更新 challenge 失败");
                return 0;
            }

            debug("result:" + resultStr);

            JSONObject jsonObject = JSONObject.parseObject(resultStr);
            String returnChallenge = jsonObject.getString("challenge");

            debug("return_challenge:" + returnChallenge);

            if (returnChallenge.length() == 32) {
                responseJson = getSuccessPreProcessRes(md5Encode(returnChallenge + privateKey));
                return 1;
            } else {
                debug("用 captchaId 进行注册，更新 challenge 错误");
                return 0;
            }
        } catch (Exception e) {
            debug(e.toString());
            debug("exception:register api");
        }
        return 0;
    }

    /**
     * 判断是否为空
     * <p>
     * 已去空格
     *
     * @param object 需要判断的对象
     * @return 返回是否为空
     */
    private boolean objectIsEmpty(Object object) {
        return object == null || object.toString().trim().length() == 0;
    }

    /**
     * 检查客户端的请求是否合法，三个只要有一个为空，则判断不合法
     *
     * @param challenge challenge
     * @param validate  validate
     * @param seccode   seccode
     * @return 返回客户端的请求是否合法
     */
    private boolean resquestIsLegal(String challenge, String validate, String seccode) {
        return objectIsEmpty(challenge) || objectIsEmpty(validate) || objectIsEmpty(seccode);
    }

    /**
     * 服务正常的情况下使用的验证方式,向gt-server进行二次验证,获取验证结果
     *
     * @param challenge challenge
     * @param validate  validate
     * @param seccode   seccode
     * @param data      包含信息：
     *                  user_id：用户标识
     *                  client_type：web：电脑上的浏览器，h5：手机上的浏览器，包括移动应用内完全内置的web_view，native：通过原生SDK植入APP应用的方式
     *                  ip_address：IP
     * @return 验证结果, 1 表示验证成功 0 表示验证失败
     * @throws UnsupportedEncodingException 转 URLEncoder 异常
     */
    private int enhencedValidateRequest(String challenge, String validate, String seccode, VerifyParam data)
            throws UnsupportedEncodingException {

        if (resquestIsLegal(challenge, validate, seccode)) {
            return 0;
        }

        debug("请求合法");

        String userId = URLEncoder.encode(data.getUserId(), "utf-8");
        String clientType = URLEncoder.encode(data.getClientType().type, "utf-8");
        String ipAddress = URLEncoder.encode(data.getIpAddress(), "utf-8");

        String param = String.format("challenge=%s&validate=%s&seccode=%s&json_format=%s", challenge, validate, seccode, JSON_FORMAT);

        StringBuilder stringBuilder = new StringBuilder(param);

        // 参数处理
        param(userId, clientType, ipAddress, stringBuilder);

        param = stringBuilder.toString();

        debug("param:" + param);

        String response = "";

        try {

            if (validate.length() <= 0) {
                return 0;
            }

            if (!checkResultByPrivate(challenge, validate)) {
                return 0;
            }

            debug("检查私人结果");

            String validateUrl = "http://api.geetest.com/validate.php";
            response = readContentFromPost(validateUrl, param);

            debug("response: " + response);
        } catch (Exception e) {
            e.printStackTrace();
        }

        JSONObject jsonObject = JSONObject.parseObject(response);

        String returnSeccode = jsonObject.getString("seccode");
        debug("md5: " + md5Encode(returnSeccode));

        return returnSeccode.equals(md5Encode(seccode)) ? 1 : 0;
    }

    /**
     * 参数处理
     *
     * @param userId        用户标识
     * @param clientType    web：电脑上的浏览器，h5：手机上的浏览器，包括移动应用内完全内置的web_view，native：通过原生SDK植入APP应用的方式
     * @param ipAddress     IP
     * @param stringBuilder StringBuilder
     */
    private void param(String userId, String clientType, String ipAddress, StringBuilder stringBuilder) {
        if (userId != null) {
            stringBuilder.append("&user_id=").append(userId);
        }
        if (clientType != null) {
            stringBuilder.append("&client_type=").append(clientType);
        }
        if (ipAddress != null) {
            stringBuilder.append("&ip_address=").append(ipAddress);
        }
    }

    /**
     * failback使用的验证方式
     *
     * @param challenge challenge
     * @param validate  validate
     * @param seccode   seccode
     * @return 返回验证结果, 1表示验证成功0表示验证失败
     */
    private int failbackValidateRequest(String challenge, String validate, String seccode) {

        debug("故障验证");

        if (resquestIsLegal(challenge, validate, seccode)) {
            return 0;
        }

        debug("请求合法");

        return 1;
    }

    /**
     * 输出debug信息，需要开启 debug
     */
    private void debug(String message) {
        if (debug) {
            System.out.println("gtlog: " + message);
        }
    }

    /**
     * 验证
     *
     * @param challenge challenge
     * @param validate  validate
     * @return 验证结果
     */
    private boolean checkResultByPrivate(String challenge, String validate) {
        String encodeStr = md5Encode(privateKey + "geetest" + challenge);
        return validate.equals(encodeStr);
    }

    /**
     * 发送GET请求，获取服务器返回结果
     *
     * @param url URL
     * @return 返回服务器返回结果
     * @throws IOException 连接异常
     */
    private String readContentFromGet(String url) throws IOException {

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();

        // 设置连接主机超时（单位：毫秒）
        connection.setConnectTimeout(2000);
        // 设置从主机读取数据超时（单位：毫秒）
        connection.setReadTimeout(2000);

        // 建立与服务器的连接，并未发送数据
        connection.connect();

        return getResponseString(connection);
    }

    /**
     * 发送POST请求，获取服务器返回结果
     *
     * @param url  URL
     * @param data POST 参数
     * @return 返回服务器返回结果
     * @throws IOException 连接异常
     */
    private String readContentFromPost(String url, String data) throws IOException {

        debug(data);

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();

        // 设置连接主机超时（单位：毫秒）
        connection.setConnectTimeout(2000);

        // 设置从主机读取数据超时（单位：毫秒）
        connection.setReadTimeout(2000);

        connection.setRequestMethod("POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        // 建立与服务器的连接，并未发送数据
        connection.connect();

        OutputStreamWriter outputStreamWriter = new OutputStreamWriter(connection.getOutputStream(), StandardCharsets.UTF_8);
        outputStreamWriter.write(data);
        outputStreamWriter.flush();
        outputStreamWriter.close();

        return getResponseString(connection);
    }

    /**
     * 读取响应
     *
     * @param connection 连接
     * @return 返回 String 类型的响应
     * @throws IOException 连接异常
     */
    private String getResponseString(HttpURLConnection connection) throws IOException {

        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {

            // 发送数据到服务器并使用 Reader 读取返回的数据
            StringBuilder stringBuilder = new StringBuilder();

            byte[] bytes = new byte[1024];

            InputStream inputStream = connection.getInputStream();

            for (int n; (n = inputStream.read(bytes)) != -1; ) {
                stringBuilder.append(new String(bytes, 0, n, StandardCharsets.UTF_8));
            }

            inputStream.close();

            // 断开连接
            connection.disconnect();

            return stringBuilder.toString();
        } else {
            return FAIL;
        }
    }

    /**
     * MD5 加密
     *
     * @param text 需要加密的字符串
     * @return 返回 MD5 加密后的字符串
     */
    private String md5Encode(String text) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(text.getBytes());
            byte[] bytes = messageDigest.digest();
            int i;
            StringBuilder buf = new StringBuilder();
            for (byte b : bytes) {
                i = b;

                i = i < 0 ? i + 256 : i;

                if (i < 16) {
                    buf.append("0");
                }

                buf.append(Integer.toHexString(i));
            }
            return buf.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static class GeetestParam {

        private final String userId;

        private final ClientType clientType;

        private final String ipAddress;

        public GeetestParam(@NotNull String userId, @NotNull ClientType clientType, @NotNull String ipAddress) {
            this.userId = userId;
            this.clientType = clientType;
            this.ipAddress = ipAddress;
        }

        private String getUserId() {
            return userId;
        }

        private ClientType getClientType() {
            return clientType;
        }

        private String getIpAddress() {
            return ipAddress;
        }

    }

    public static class VerifyParam {

        private final ClientType clientType;

        private final String ipAddress;

        private String userId;

        public VerifyParam(@NotNull ClientType clientType, @NotNull String ipAddress) {
            this.clientType = clientType;
            this.ipAddress = ipAddress;
        }

        private ClientType getClientType() {
            return clientType;
        }

        private String getIpAddress() {
            return ipAddress;
        }

        private void setUserId(String userId) {
            this.userId = userId;
        }

        private String getUserId() {
            return userId;
        }

    }

    public enum ClientType {

        /**
         * 电脑上的浏览器
         */
        WEB("web"),

        /**
         * 手机上的浏览器
         * 包括移动应用内完全内置的web_view
         */
        H5("h5"),

        /**
         * 通过原生SDK植入APP应用的方式
         */
        NATIVE("native");

        private final String type;

        ClientType(String type) {
            this.type = type;
        }

    }

}
