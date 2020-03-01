package com.spring.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = "/")
public class LoginController {

    @GetMapping(value = "login")
    public String login(){
        return "login";
    }

    @GetMapping(value = "logout")
    public String logout(){
        return "logout";
    }

    @GetMapping(value = "success")
    public String success()
    {
        return "success";
    }
}
