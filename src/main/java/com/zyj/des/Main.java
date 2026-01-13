package com.zyj.des;

import com.zyj.des.util.DesUtil;

public class Main {
    public static void main(String[] args) {
        String helloWorld = DesUtil.encrypt("hello worlduiop", "123456");
        System.out.println("加密: " + helloWorld);
        System.out.println("最终解密后的明文：" + DesUtil.decrypt(helloWorld, "123456"));
    }
}
