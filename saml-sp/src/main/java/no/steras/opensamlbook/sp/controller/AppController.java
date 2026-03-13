package no.steras.opensamlbook.sp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class AppController {

    @GetMapping("/app/appservlet")
    @ResponseBody
    public String protectedResource() {
        return "<h1>You are now at the requested resource</h1>" +
                "This is the protected resource. You are authenticated";
    }
}
