package com.zyj.des.controller;

import com.zyj.des.core.DesCipher;
import com.zyj.des.util.DesUtil;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {
    @GetMapping("/encrypt")
    public String encrypt(@RequestParam("plainText") String plainText, @RequestParam("secretKey") String secretKey) {
        return DesUtil.encrypt(new DesCipher(plainText, secretKey));
    }
    @GetMapping("/decrypt")
    public String decrypt(@RequestParam("cipherText") String cipherText, @RequestParam("secretKey") String secretKey) {
        return DesUtil.decrypt(cipherText, secretKey);
    }
}
