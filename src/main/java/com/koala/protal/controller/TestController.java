//package com.koala.protal.controller;
//
//import com.koala.member.api.MemberService;
//import com.koala.member.api.response.UserInfo;
//import com.koala.utils.common.define.JsonResult;
//import com.koala.utils.common.define.ResultCode;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import javax.annotation.Resource;
//import javax.websocket.server.PathParam;
//import java.util.Date;
//
///**
// * @Author Liuyf
// * @Date 2016-08-08
// * @Time 16:09
// * @Description
// */
//@RestController(value = "/")
//public class TestController {
//
//    @Resource
//    private MemberService memberService;
//
//    @RequestMapping(value = "/")
//    public JsonResult home() {
//        UserInfo userInfo = new UserInfo();
//        userInfo.setUserName("111");
//        userInfo.setPassword("111");
//        userInfo.setRealName("yiyiyi");
//        userInfo.setDesc("eeee");
//        userInfo.setCreateId(1L);
//        userInfo.setCreateDate(new Date());
//        userInfo.setUpdateId(1L);
//        userInfo.setUpdateDate(new Date());
//        memberService.saveUser(userInfo);
//        return new JsonResult(ResultCode.SUCCESS,"访问成功", userInfo.getUserName());
//    }
//
//    @RequestMapping(value = "/get/{id}")
//    public JsonResult getUser(@PathVariable Long id){
//        UserInfo ui = memberService.getUserById(id);
//        return new JsonResult(ResultCode.SUCCESS,"",ui.getCreateDate());
//    }
//
//}
