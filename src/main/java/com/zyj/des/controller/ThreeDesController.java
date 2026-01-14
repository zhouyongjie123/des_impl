package com.zyj.des.controller;

import com.zyj.des.util.DesUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/three")
public class ThreeDesController {
    @GetMapping("/encrypt")
    public String encrypt(
            @RequestParam("plainText") String plainText, @RequestParam("key1") String key1,
            @RequestParam("key2") String key2, @RequestParam("key3") String key3) {
        return DesUtil.encrypt(DesUtil.decrypt(DesUtil.encrypt(plainText, key1), key2), key3);
    }
    // 解密
    @GetMapping("/decrypt")
    public String decrypt(
            @RequestParam("cipherText") String cipherText, @RequestParam("key1") String key1,
            @RequestParam("key2") String key2, @RequestParam("key3") String key3) {
        return DesUtil.decrypt(DesUtil.encrypt(DesUtil.decrypt(cipherText, key3), key2), key1);
    }
}
