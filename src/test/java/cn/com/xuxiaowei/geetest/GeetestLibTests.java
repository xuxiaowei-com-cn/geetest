/*
 * Copyright 2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cn.com.xuxiaowei.geetest;

import com.alibaba.fastjson.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * 极验 Java SDK 使用方法
 * <p>
 * 直接在 Controller、Servlet 中使用
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class GeetestLibTests {

    private final String captchaId = "";

    private final String privateKey = "";

    private final boolean newFailback = true;

    private final GeetestLib geetestLib = new GeetestLib(captchaId, privateKey, newFailback);

    /**
     * 获取极验
     *
     * @param request 请求
     * @return 返回极验
     */
    public JSONObject geetest(HttpServletRequest request) {
        return geetestLib.geetest(request, new GeetestLib.GeetestParam("test", GeetestLib.ClientType.WEB, "127.0.0.1"));
    }

    /**
     * 验证极验
     * <p>
     * 布尔值使用 {@link GeetestLib#verify(HttpServletRequest, GeetestLib.VerifyParam)}
     *
     * @param request 请求
     * @return 返回极验验证结果
     */
    public JSONObject verify(HttpServletRequest request) throws IOException {
        return geetestLib.verifyJson(request, new GeetestLib.VerifyParam(GeetestLib.ClientType.WEB, "127.0.0.1"));
    }

}
